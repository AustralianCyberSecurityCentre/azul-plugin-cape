"""Handle the API requests to CAPE on behalf of the plugin."""

import datetime
import logging
import time
from typing import Optional

import httpx
from azul_runner import Job, settings

logger = logging.getLogger(__name__)


class CapeError(RuntimeError):
    """Exception raised to indicate that the CAPE returned a failure condition to a request.

    Optional second parameter `cape_message` records the message returned by cape.
    """

    cape_message: str = None  # Error message returned by cape

    def __init__(self, message=None, cape_message: str = None):
        super().__init__(message)
        self.cape_message = cape_message


def _check_error(resp: httpx.Response, context: str):
    """Utility function to check if cape returned an error and raise a CapeError if so."""
    # Raise an exception for non-'OK' responses
    try:
        resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise httpx.HTTPStatusError(
            f"Failed to query cape during context {context} with error {e}", request=e.request, response=e.response
        )

    # Check for CAPE errors if the response is JSON
    if resp.headers["content-type"].startswith("application/json") and resp.json().get("error", False):
        # Note that the JSON for /report/ does NOT seem to contain {'error': False, ...} if it succeeded,
        #  so we need to use get() rather than resp.json()['error'] as the key may be absent.
        logger.fatal(f"CAPE error {context}: " + resp.json()["error_value"])
        raise CapeError(f"CAPE returned error {context}", cape_message=resp.json()["error_value"])


class CapeIO:
    """Methods for handling plugin tasks for CAPE, such as submitting and waiting for jobs, or fetching a report."""

    client: httpx.Client

    def __init__(self, cfg: settings.Settings):
        self.cfg = cfg

    def __enter__(self):
        """Open a connection to cape."""
        if self.cfg.cape_auth_token:
            auth_header = {"Authorization": f"Token {self.cfg.cape_auth_token}"}
        else:
            auth_header = None

        self.client = httpx.Client(
            base_url=f"{self.cfg.cape_server}/apiv2",
            headers=auth_header,
            transport=httpx.HTTPTransport(retries=self.cfg.api_retry_count),
            timeout=self.cfg.request_timeout,
        )

        logger.info(
            f"Initialised with base url '{self.cfg.cape_server}/apiv2', {self.cfg.request_timeout}s timeout and "
            "{self.cfg.api_retry_count} retries"
        )
        return self

    def __exit__(self, *args, **kwargs):
        """Close the connection to cape."""
        self.client.close()

    def is_cape_contactable(self) -> tuple[bool, httpx.HTTPStatusError]:
        """Check if the cape VM is contactable and return error if it isn't."""
        response = self.client.get("/")
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as e:
            return False, e
        return True, ""

    def find_or_submit(self, job: Job) -> int:
        """Checks for an existing job for this file in CAPE, and submits the file if not present.

        Returns the task ID of the file in cape.
        """
        # Check whether CAPE already knows about this sample
        # Use /tasks/search rather than /files/view because the latter gives wrong IDs if tasks have been deleted
        response = self.client.get(f"/tasks/search/sha256/{job.event.entity.sha256}/")
        _check_error(response, "checking if file already present")
        if len(response.json()["data"]) != 0:
            # CAPE returns a list in reverse-chronological order, so we want the first one
            #  (since that is actually the latest run)
            tasklist = [e["id"] for e in response.json()["data"]]
            if len(tasklist) > 1:
                logger.warning(f"More than one CAPE task found for this entity {tasklist}; using the first one")
            cape_id = tasklist[0]
            logger.info(f"Found entity already in CAPE with id {cape_id}")
        else:
            # Need to submit job to CAPE
            filenames = [f.value for f in job.event.entity.features if f.name == "filename"]
            # CAPE accepts either (name, data-stream) or just bare data-stream in file submission
            file_submission = (sorted(filenames)[0], job.get_data()) if filenames else job.get_data()
            response = self.client.post("/tasks/create/file/", files={"file": file_submission})
            # Optionally we can also pass `data={"machine": "vm-name"}` to request a specific guest
            _check_error(response, "submitting job")
            tasklist = response.json()["data"]["task_ids"]
            if len(tasklist) != 1:
                logger.warning(f"CAPE returned more than one tasks for submission {tasklist}; using the first one")
            cape_id = tasklist[-1]

        return cape_id

    def wait_for_completion(self, cape_id: int) -> None:
        """Wait until the specified CAPE job is completed, or raise CapeError if the job does not start processing."""
        # Get the submitted time from the 'view' page, in case it was submitted by an earlier run
        # Used to test whether to give up on the job (cfg.start_timeout)
        response = self.client.get(f"/tasks/view/{cape_id}/")
        _check_error(response, "while fetching tasks/view/")
        # Timestamp is in the format '2024-01-22 03:51:58'
        submit_time = datetime.datetime.fromisoformat(response.json()["data"]["added_on"])

        # Check job status and wait for completion if necessary
        # Waiting is done outside of check-existence/submit block in case job was submitted but isn't done yet
        while True:
            response = self.client.get(f"/tasks/status/{cape_id}/")
            _check_error(response, "while fetching job status")
            status = response.json()["data"]

            if status == "reported":
                # Expected statuses are 'pending', 'running', 'distributed', 'completed', 'recovered', 'reported'
                # Process should be pending -> running -> completed -> reported
                break

            if status.startswith("failed_"):
                # CAPE lists 'failed_analysis', 'failed_processing', 'failed_reporting' as categories
                logger.fatal(f"CAPE job error: {status}")
                # It's unclear whether this is actually an 'exception' vs 'network error', but experience suggests
                #  that in most cases CAPE failures are due to non-transient reasons (can't handle the sample)
                raise CapeError(f"CAPE job error: {status}")

            time_waited = (datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - submit_time).seconds
            if status == "pending":
                # If job stays as 'pending' for too long, assume CAPE is not processing it and abort with an error
                if time_waited > self.cfg.start_timeout:
                    logger.fatal(f"CAPE did not start processing within {self.cfg.start_timeout} seconds")
                    raise CapeError(f"CAPE did not start processing within {self.cfg.start_timeout} seconds")
            logger.info(f"Waiting for job to be reported ({time_waited}s) - cape reports status '{status}'")
            time.sleep(self.cfg.poll_interval)

    def fetch_job_report(self, cape_id: int) -> dict:
        """Fetch the CAPE JSON report for a given task as a python dict."""
        response = self.client.get(f"/tasks/get/report/{cape_id}/")
        _check_error(response, "while fetching job report")
        return response.json()

    def fetch_screenshots(self, cape_id: int) -> Optional[bytes]:
        """Fetch the screenshot ZIP for the specified cape task, or None if no screenshots exist."""
        response = self.client.get(f"/tasks/get/screenshot/{cape_id}/")
        if response.status_code == 500:
            # CAPE returns a server error if the screenshots directory is missing, so treat it as "no screenshots"
            return None
        _check_error(response, "while fetching screeshots")
        return response.content
