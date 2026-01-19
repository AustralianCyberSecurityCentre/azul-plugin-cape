"""Submit binaries to CAPE dynamic analysis."""

import io
import json
import logging
import re
import tempfile
import traceback
import zipfile
from typing import Dict

import httpx
from azul_bedrock.models_network import FeatureType
from azul_runner import (
    FV,
    BinaryPlugin,
    DataLabel,
    Feature,
    Job,
    State,
    add_settings,
    cmdline_run,
)
from PIL import Image

from .cape import CapeError, CapeIO

ftInt, ftFloat, ftStr = (FeatureType.Integer, FeatureType.Float, FeatureType.String)
logger = logging.getLogger(__name__)


class AzulPluginCape(BinaryPlugin):
    """Submit binaries to CAPE dynamic analysis."""

    VERSION = "2025.02.07"
    SETTINGS = add_settings(
        # Note: 'win32 exe' may include 64-bit exes
        filter_data_types={
            "content": [
                "executable/windows/pe",
                "executable/windows/pe32",
                "executable/windows/pe64",
                "executable/pe32",
            ]
        },
        run_timeout=20 * 60,  # We expect CAPE runs to take a while
        filter_max_content_size="16MiB",  # File size to process
        request_timeout=30,  # How long to wait for the server before error
        # custom options
        start_timeout=(int, 10 * 60),  # Report error if CAPE doesn't start running the sample within this time
        cape_server=(str, ""),  # URL of the CAPE server, eg http://localhost:8000
        cape_auth_token=(str, ""),  # Token for server auth, or empty for none
        poll_interval=(int, 15),  # Seconds to wait between polling of CAPE server for job status
        api_retry_count=(int, 3),  # How many times to retry API requests on timeout or temporary error
        concurrent_plugin_instances=10,  # Number of copies of the plugin to run simultaneously in the same container.
    )
    FEATURES = [
        Feature("attack", desc="Mitre att&ck reference ids, e.g. 'T1129'", type=ftStr),
        Feature("behaviour_signature", desc="Behavioural signature name that the sample triggered", type=ftStr),
        Feature("cape_malscore", desc="CAPE's guess at how malicious this file is", type=ftFloat),
        Feature("command_executed", desc="Command line executed by process during analysis", type=ftStr),
        Feature("contacted_host", desc="Network endpoint seen communicating to", type=ftStr),
        Feature("contacted_port", desc="Destination port and protocol seen communicating on", type=ftInt),
        Feature("contacted_url", desc="Network URL the sample was observed communicating with", type=ftStr),
        Feature("domain", desc="Domain name observed or extracted from the sample", type=ftStr),
        Feature("file_read", desc="Filepath read by process during dynamic analysis", type=ftStr),
        Feature("file_written", desc="Filepath written by process during dynamic analysis", type=ftStr),
        Feature("file_deleted", desc="Filepath deleted by process during dynamic analysis", type=ftStr),
        Feature("ip_address", desc="IP address observed or extracted from the sample", type=ftStr),
        Feature("registry_read", desc="Registry key read by the process during dynamic analysis", type=ftStr),
        Feature("registry_key_set", desc="Registry key set by process during dynamic analysis", type=ftStr),
        Feature("registry_key_deleted", desc="Registry key deleted during dynamic analysis", type=ftStr),
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if not self.cfg.cape_server:
            raise RuntimeError("CAPE server URL must be set")
        if not httpx.URL(self.cfg.cape_server).is_absolute_url:
            raise RuntimeError(f"Unable to use CAPE server with URL '{self.cfg.cape_server}'")

        # Convert configs to integers if they aren't (config from env is always strings)
        for cfg_var in (
            "start_timeout",
            "poll_interval",
            "api_retry_count",
        ):
            try:
                setattr(self.cfg, cfg_var, int(getattr(self.cfg, cfg_var)))
            except ValueError as e:
                raise ValueError(f"Config setting {cfg_var} must be an int value") from e

    def execute(self, job: Job):
        """Run the plugin."""
        try:
            with CapeIO(self.cfg) as cape_io:
                return self.execute_body(job, cape_io)
        except httpx.RequestError as exc:
            # RequestError covers everything that could be due to network state,  such as timeouts,
            #  connection failures and protocol errors, but not response-code errors (eg 404, 500 etc)
            return State(State.Label.ERROR_NETWORK, exc.args[0], "".join(traceback.format_exc()))
        except CapeError as exc:
            return State(State.Label.ERROR_EXCEPTION, exc.args[0], exc.cape_message)

    def execute_body(self, job: Job, cape_io: CapeIO):
        """Main body of the plugin run, wrapped by a network exception handler in execute()."""
        is_contactable, httpx_status_error = cape_io.is_cape_contactable()
        if not is_contactable:
            resp = httpx_status_error.response
            return State(
                State.Label.ERROR_NETWORK,
                failure_name="Cape Uncontactable",
                message="Cape could not be contacted, with status"
                + f" code {resp.status_code} {resp.reason_phrase} for url '{resp.url}'",
            )

        cape_task = cape_io.find_or_submit(job)
        cape_io.wait_for_completion(cape_task)
        cape_report = cape_io.fetch_job_report(cape_task)

        if cape_report.get("info", {}).get("machine", {}).get("name", None) is None:
            return State(State.Label.ERROR_EXCEPTION, "Cape guest machine name missing, assuming execution failed")

        # Add cape's execution log as a text artifact, if non-null
        if cape_report["debug"]["log"]:
            self.add_text(cape_report["debug"]["log"])

        # Add the full cape report (JSON) as a data stream for use by downstream plugins
        self.add_data(DataLabel.CAPE_REPORT, data=json.dumps(cape_report).encode("utf-8"), tags={})

        # Record CAPE's "malscore"
        self.add_feature_values("cape_malscore", [cape_report["malscore"]])

        # Add 'signatures' (suspicious behaviours) as tags
        # These are things like 'modify_proxy', 'dynamic_function_loading' etc
        self.add_feature_values(
            "behaviour_signature",
            [
                FV(s["name"], label=f"{s['description']} (Severity: {s['severity']} Confidence: {s['confidence']})")
                for s in cape_report["signatures"]
            ],
        )

        # Add features for the ATT&CK techniques returned in cape_report['ttps']
        # This is a subset of 'signatures', just the ones that have ATT&CK IDs
        self.add_feature_values("attack", [FV(a["ttp"], label=a["signature"]) for a in cape_report["ttps"]])

        # Record features for file and registry accesses
        for feat_name, cape_name in [
            ("file_read", "read_files"),
            ("file_written", "write_files"),
            ("file_deleted", "delete_files"),
            ("registry_read", "read_keys"),
            ("registry_key_set", "write_keys"),
            ("registry_key_deleted", "delete_keys"),
            ("command_executed", "executed_commands"),
        ]:
            if cape_report["behavior"]["summary"][cape_name]:
                self.add_feature_values(feat_name, cape_report["behavior"]["summary"][cape_name])

        # Network features
        if "domains" in cape_report["network"]:
            self.add_feature_values(
                "domain", [FV(i["domain"], label="DNS lookup") for i in cape_report["network"]["domains"]]
            )

        if "http" in cape_report["network"]:
            self.add_feature_values(
                "contacted_url",
                [
                    FV(i["uri"], label=f"{i['method']}, count={i['count']}, user-agent={i['user-agent']}")
                    for i in cape_report["network"]["http"]
                ],
            )

        # Make a list of IPs returned by DNS lookup so as not to include them in IP features
        resolved_ips = set()
        for req in cape_report["network"].get("dns", []):
            resolved_ips.update({ans["data"] for ans in req["answers"] if ans["type"] in ("A", "AAAA")})

        contacted_ips = {}
        contacted_ports = set()
        for ctype in ("tcp", "udp"):
            for conn in cape_report["network"].get(ctype, []):
                contacted_ports.add(FV(conn["dport"], label=ctype))
                if conn["dst"] in resolved_ips:
                    # Don't include the IPs we looked up from DNS; we only want to see direct IP connections
                    continue
                # Build a dict of {ip: set('tcp:<port>', 'tcp:<port>', 'udp:<port>', ...)}
                contacted_ips.setdefault(conn["dst"], set()).add(f"{ctype}:{conn['dport']}")

        self.add_feature_values(
            "contacted_host", [FV(ip, label="".join(sorted(ports))) for ip, ports in contacted_ips.items()]
        )
        self.add_feature_values("ip_address", sorted(contacted_ips.keys()))
        self.add_feature_values("contacted_port", contacted_ports)

        # Fetch and add screenshots from the run
        if zip_bytes := cape_io.fetch_screenshots(cape_task):
            with tempfile.SpooledTemporaryFile(max_size=2**23) as temp_zip:
                temp_zip.seekable = lambda: True  # Required because ZipFile checks this
                # Write the content of the zip to the temp file, then free the byte string
                temp_zip.write(zip_bytes)
                del zip_bytes
                # Sort the screenshots by name, since they're not ordered in the zip directory
                screenshot: Dict[str, Image] = {}
                with zipfile.ZipFile(temp_zip) as zf:
                    for zip_entry in zf.infolist():
                        # Iterate each entry in the zip and add to our dict, indexed by sequence number (0000, 0001...)
                        if zip_entry.is_dir():
                            logger.warning(f"Unexpected subdirectory '{zip_entry.filename}' found in screenshots zip")
                            continue
                        if not re.fullmatch(r"shots/[\d]{4}\.jpg", zip_entry.filename):
                            raise RuntimeError(
                                "CAPE screenshots have unexpected filename format - plugin needs update?"
                            )
                        shot_seq = zip_entry.filename[6:10]
                        shot_img = Image.open(zf.open(zip_entry))
                        # Read and close the file object for the zipped image, so we can close the zip at loop end
                        shot_img.load()
                        screenshot[shot_seq] = shot_img
            # Form a list of Image objects in the correct sequence
            image_list = [screenshot[seq] for seq in sorted(screenshot.keys())]
            image_count = len(image_list)
            if image_count == 0:
                logger.warning("CAPE returned an empty screenshot zip; treating as no screenshots exist")
                webp_hash = ""
            else:
                webp_file = io.BytesIO()
                first_img = image_list.pop(0)
                # Saves an animated WebP, starting with the first image and appending the rest of the list as frames
                first_img.save(
                    webp_file, format="WebP", quality=80, save_all=True, append_images=image_list, duration=500
                )
                # Free the individual frame images now that we have the webp file
                del image_list, screenshot
                webp_hash = self.add_data_file(DataLabel.SCREENSHOT, data_file=webp_file, tags={})
                del webp_file  # add_data_file stores the data; we don't need to keep it any more
        else:
            image_count = 0
            webp_hash = ""

        self.add_info(
            {
                "CAPE_machine": cape_report["info"]["machine"]["name"],
                "screenshot_hash": webp_hash,
                "screenshot_count": image_count,
            }
        )


def main():
    """Plugin command-line entrypoint."""
    cmdline_run(plugin=AzulPluginCape)


if __name__ == "__main__":
    main()
