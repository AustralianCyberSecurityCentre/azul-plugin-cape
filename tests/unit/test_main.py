"""Test cases for plugin output."""

import ast
import datetime
import hashlib
import io
import itertools
import json
import zipfile
from typing import Dict, List

import httpx
import pytest
from azul_runner import (
    DATA_HASH,
    FV,
    DataLabel,
    Event,
    EventData,
    EventParent,
    JobResult,
    State,
    test_template,
)
from PIL import Image, ImageChops, ImageSequence

from azul_plugin_cape.main import AzulPluginCape

from ._util import _compare_img_seqs, _make_img_zip

# Define these here so that tests can reference them as needed.
# This report is returned by the hook_http() function's fake CAPE server unless overridden
dummy_report = {
    "error": 0,
    "debug": {"log": ""},
    "info": {"machine": {"name": "TestCapeMachine"}},
    "malscore": 0.0,
    "signatures": [],
    "ttps": [],
    "behavior": {
        "summary": {
            "read_files": [],
            "write_files": [],
            "delete_files": [],
            "read_keys": [],
            "write_keys": [],
            "delete_keys": [],
            "executed_commands": [],
        },
    },
    "network": {},
}
dummy_report_stream = json.dumps(dummy_report).encode("utf8")
dummy_report_hash = hashlib.sha256(dummy_report_stream).hexdigest()


def hook_http(monkeypatch, overrides={}):
    """Hook httpx.Client.get and httpx.Client.post to simulate a CAPE run.

    Passing in str:dict or str:list pairs to `overrides` will use matching entries instead of the default response.
    Each key str is matched literally with `<k> in <url>`, use eg 'apiv2/tasks/search/sha256/'.
    Each value should have one of:
     - a dict (which is returned as the .json() value of the response),
     - an httpx.Response (typically with an error code) which is returned directly
     - an Exception, which is raised
     - a `bytes` value, which is returned as the "content" attribute of the Response (eg screenshots)
     - or a list of any of these, which are returned sequentially each time the url matches the key."""
    # Caller should override /tasks/view to use different submit time value
    fake_submit_time = datetime.datetime.now(datetime.timezone.utc)
    hit_counts: Dict[str, int] = {}  # How many times we've matched a particular url entry.
    defaults = {
        # '/tasks/search/sha256/': {'error': 0, 'data': [{'id': 1}]}, # Simulate file exists in CAPE
        "/tasks/search/sha256/": {"error": 0, "data": []},  # Simulate file not found in CAPE
        "/tasks/create/file/": {"error": 0, "data": {"task_ids": [1]}},
        "/tasks/view/": {"error": 0, "data": {"added_on": str(fake_submit_time)[:19]}},
        "/tasks/status/": [
            {"error": 0, "data": "pending"},
            {"error": 0, "data": "running"},
            {"error": 0, "data": "completed"},
            {"error": 0, "data": "reported"},
        ],
        "/tasks/get/report/": dummy_report,
        "/tasks/get/screenshot/": httpx.Response(500),  # Simulate no screenshots exist; we test them later
        "/": {},
    }

    def get_hook(self, url, method="GET", **kwargs):
        # 'self' parameter is the httpx.Client instance
        req = self.build_request(method, url, **kwargs)
        for match, response in itertools.chain(overrides.items(), defaults.items()):
            if match in url:
                # If it's a list, grab the appropriate entry
                if isinstance(response, list):
                    i = hit_counts.get(match, 0)
                    if i + 1 < len(response):
                        hit_counts[match] = i + 1
                    response = response[i]
                # Handle the response
                if isinstance(response, httpx.Response):
                    response.request = req
                    return response
                elif isinstance(response, dict):
                    r = httpx.Response(200, request=req, headers={"Content-Type": "application/json"})
                    r.json = lambda: response
                    return r
                elif isinstance(response, bytes):
                    r = httpx.Response(200, request=req, content=response, headers={"Content-Type": "application/zip"})
                    return r
                elif isinstance(response, Exception):
                    response.request = req  # httpx sets this on its exceptions, caller may need it
                    raise response
                raise RuntimeError(f"Invalid value type in mock response table: {response}")
        raise RuntimeError(f"No matching mock responses found for request {url}")

    def post_hook(self, url, **kwargs):
        return get_hook(self, url, method="POST", **kwargs)

    monkeypatch.setattr("httpx.Client.get", get_hook)
    monkeypatch.setattr("httpx.Client.post", post_hook)


class TestExecute(test_template.TestPlugin):
    PLUGIN_TO_TEST = AzulPluginCape
    PLUGIN_TO_TEST_CONFIG = {"cape_server": "https://cape.internal"}

    _test_imgs: List[Image.Image] = []  # Sequence of images generated for testing screenshots

    @classmethod
    def setup_class(cls):
        # Generate some dummy images for the "screenshots" so we can verify that they are returned correctly
        for _ in range(3):
            # use 80x60 pixels to not pass around too much data during testing.
            im = Image.effect_noise((80, 60), sigma=96.0).convert("RGB")
            cls._test_imgs.append(im)

    @pytest.fixture(autouse=True)
    def _fixture_hook(self, monkeypatch, caplog):
        # pytest doesn't seem to support directly declaring fixtures as params in class methods
        self.mp = monkeypatch
        self.caplog = caplog

    def test_no_URL(self):
        """Tests for expected error when server URL is not set"""
        data = self.load_test_file_bytes(
            "8216f8d097740bcdaa1d0e9144e0e0afbc6e4c817b1cf15e8ae37244065cd129",
            "Cheat engine installer executable version 6.1.",
        )
        with pytest.raises(RuntimeError, match="CAPE server URL must be set"):
            result = self.do_execution(data_in=[("content", data)], config={})

    def test_invalid_URL(self):
        """Tests for expected error when given an invalid server URL"""
        data = self.load_test_file_bytes(
            "8216f8d097740bcdaa1d0e9144e0e0afbc6e4c817b1cf15e8ae37244065cd129",
            "Cheat engine installer executable version 6.1.",
        )
        with pytest.raises(RuntimeError, match="Unable to use CAPE server with URL 'not a valid URL'"):
            result = self.do_execution(data_in=[("content", data)], config={"cape_server": "not a valid URL"})

    def test_cape_server_500_error(self):
        """Test that if the cape server is not working an appropriate error is provided."""
        hook_http(self.mp, overrides={"/": httpx.Response(500)})
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "8216f8d097740bcdaa1d0e9144e0e0afbc6e4c817b1cf15e8ae37244065cd129",
                        "Cheat engine installer executable version 6.1.",
                    ),
                )
            ],
            config={"cape_server": "http://dummy/", "poll_interval": 1},
            no_multiprocessing=True,
        )
        # verify there is the status code somewhere in the message and discard the rest as it may change.
        self.assertIn("500", result.state.message)
        result.state.message = ""
        self.assertEqual(
            result, JobResult(state=State(State.Label.ERROR_NETWORK, failure_name="Cape Uncontactable", message=""))
        )

    def test_string_config_values(self):
        """Passing values in from the environment will give configs that are strings, check plugin handles them"""
        data = self.load_test_file_bytes(
            "8216f8d097740bcdaa1d0e9144e0e0afbc6e4c817b1cf15e8ae37244065cd129",
            "Cheat engine installer executable version 6.1.",
        )
        hook_http(self.mp)

        result = self.do_execution(
            data_in=[("content", data)],
            config={
                "cape_server": "http://dummy/",
                "start_timeout": "600",
                "poll_interval": "1",
                "api_retry_count": "3",
            },
            no_multiprocessing=True,
        )
        # This run should return a minimal result with no features except malscore
        assert dummy_report_hash in result.data
        assert result.data[dummy_report_hash].read() == dummy_report_stream
        result.data.clear()
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id=hashlib.sha256(data).hexdigest(),
                        features={"cape_malscore": [FV(0.0)]},
                        data=[EventData(hash=dummy_report_hash, label=DataLabel.CAPE_REPORT)],
                        info={
                            "CAPE_machine": "TestCapeMachine",
                            "screenshot_hash": "",
                            "screenshot_count": 0,
                        },
                    ),
                ],
            ),
        )

    def test_client_error_abort(self):
        """Test that plugin returns the expected error when receiving a client error response."""
        data = self.load_test_file_bytes(
            "8216f8d097740bcdaa1d0e9144e0e0afbc6e4c817b1cf15e8ae37244065cd129",
            "Cheat engine installer executable version 6.1.",
        )
        hook_http(
            self.mp,
            overrides={
                "/tasks/search/sha256/": {"error": 0, "data": [{"id": 1}]},  # Simulate file present
                "/tasks/status/": [
                    # Simulate an error response
                    httpx.Response(404),
                    {"error": 1, "error_value": "Test failure, did not abort on 404"},  # Should not reach this
                ],
            },
        )
        result = self.do_execution(
            data_in=[("content", data)],
            config={"cape_server": "http://dummy/", "api_retry_count": 3, "poll_interval": 1},
            no_multiprocessing=True,
        )

        self.assertJobResult(
            result,
            JobResult(
                state=State(
                    State.Label.ERROR_EXCEPTION,
                    failure_name="HTTPStatusError",
                    message=result.state.message,  # Checked with assertion below
                )
            ),
        )
        self.assertIn(
            "HTTPStatusError: Client error '404 Not Found' for url 'http://dummy//apiv2/tasks/status/1/'",
            result.state.message,
        )

    def test_successful_run(self):
        """Test a simulated successful run with detailed output from a small dummy report"""
        data = self.load_test_file_bytes(
            "8216f8d097740bcdaa1d0e9144e0e0afbc6e4c817b1cf15e8ae37244065cd129",
            "Cheat engine installer executable version 6.1.",
        )
        # Define a report with details to check features are set correctly
        cape_report = {
            "error": 0,
            "debug": {"log": "Dummy run log"},
            "malscore": 1.3,
            "info": {
                "machine": {
                    "name": "TestCapeGuest",
                },
            },
            "signatures": [
                {
                    "name": "reads_self",
                    "severity": 2,
                    "confidence": 30,
                    "description": "Reads data out of its own binary image",
                },
                {
                    "name": "recon_programs",
                    "severity": 3,
                    "confidence": 20,
                    "description": "Collects information about installed applications",
                },
            ],
            "ttps": [
                {"ttp": "T1012", "signature": "recon_programs"},
                {"ttp": "T1082", "signature": "recon_programs"},
                {"ttp": "T1518", "signature": "recon_programs"},
            ],
            "behavior": {
                "summary": {
                    "read_files": ["c:\\example-read1.file", "c:\\example-read2.file"],
                    "write_files": ["c:\\example-write.file"],
                    "delete_files": ["c:\\temp\\example-deleted.file"],
                    "read_keys": ["REG_READ_1", "REG_READ_2"],
                    "write_keys": [],
                    "delete_keys": ["REG_DELETED"],
                    "executed_commands": ["c:\\temp\\runme.exe"],
                }
            },
            "network": {
                # Key/values not used by plugin left out of some of the below lists
                "domains": [{"domain": "google.com", "ip": "1.2.3.4"}],
                "http": [{"count": 1, "uri": "http://google.com/", "user-agent": "TestingUA", "method": "GET"}],
                "dns": [{"request": "google.com", "answers": [{"type": "A", "data": "1.2.3.4"}]}],
                "udp": [{"dst": "8.8.8.8", "dport": 53}, {"dst": "1.2.3.4", "dport": 53}],
                "tcp": [{"dst": "1.2.3.4", "dport": 80}, {"dst": "5.6.7.8", "dport": 9876}],
            },
        }
        hook_http(self.mp, overrides={"/tasks/get/report/": cape_report})

        # Expected output
        log_result = b"Dummy run log"
        log_hash = hashlib.sha256(log_result).hexdigest()
        rept_stream = json.dumps(cape_report).encode("utf8")
        rept_hash = hashlib.sha256(rept_stream).hexdigest()

        result = self.do_execution(
            data_in=[("content", data)],
            config={"cape_server": "http://dummy/", "poll_interval": 1},
            no_multiprocessing=True,
        )

        assert log_hash in result.data
        assert result.data[log_hash].read() == log_result
        assert rept_hash in result.data
        assert result.data[rept_hash].read() == rept_stream
        result.data.clear()  # Erase the data from result, as the BufferedRandom can't be easily compared

        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id=hashlib.sha256(data).hexdigest(),
                        data=[
                            EventData(hash=log_hash, label="text"),
                            EventData(hash=rept_hash, label=DataLabel.CAPE_REPORT),
                        ],
                        features={
                            "attack": [
                                FV("T1012", label="recon_programs"),
                                FV("T1082", label="recon_programs"),
                                FV("T1518", label="recon_programs"),
                            ],
                            "behaviour_signature": [
                                FV(
                                    "reads_self",
                                    label="Reads data out of its own binary image (Severity: 2 Confidence: 30)",
                                ),
                                FV(
                                    "recon_programs",
                                    label="Collects information about installed applications (Severity: 3 Confidence: 20)",
                                ),
                            ],
                            "cape_malscore": [FV(1.3)],
                            "command_executed": [FV("c:\\temp\\runme.exe")],
                            "file_read": [
                                FV("c:\\example-read1.file"),
                                FV("c:\\example-read2.file"),
                            ],
                            "file_written": [FV("c:\\example-write.file")],
                            "file_deleted": [FV("c:\\temp\\example-deleted.file")],
                            "registry_read": [FV("REG_READ_1"), FV("REG_READ_2")],
                            # Expect 'write_keys' to be missing
                            "registry_key_deleted": [FV("REG_DELETED")],
                            "domain": [FV("google.com", label="DNS lookup")],
                            "contacted_url": [FV("http://google.com/", label="GET, count=1, user-agent=TestingUA")],
                            "ip_address": [FV("5.6.7.8"), FV("8.8.8.8")],
                            "contacted_host": [FV("5.6.7.8", label="tcp:9876"), FV("8.8.8.8", label="udp:53")],
                            "contacted_port": [FV(53, label="udp"), FV(80, label="tcp"), FV(9876, label="tcp")],
                        },
                        info={
                            "CAPE_machine": "TestCapeGuest",
                            "screenshot_hash": "",
                            "screenshot_count": 0,
                        },
                    ),
                ],
            ),
        )

    def test_successful_run_with_real_report(self):
        """Test a simulated successful run with a (truncated) dump of a real CAPE report"""
        data = self.load_test_file_bytes(
            "8216f8d097740bcdaa1d0e9144e0e0afbc6e4c817b1cf15e8ae37244065cd129",
            "Cheat engine installer executable version 6.1.",
        )
        # This is a dump from a CAPE run of the "Cheat Engine" binary, with some logs and file lists truncated for size
        cape_report = ast.literal_eval(
            self.load_local_raw(
                "u_cheatengine_cape_report.txt", description="Cape report from submitting the cheat engine executable."
            ).decode("utf8")
        )

        hook_http(
            self.mp,
            overrides={
                "/tasks/get/report/": cape_report,
            },
        )

        # Check the returned log stream matches
        log_result = cape_report["debug"]["log"].encode("utf8")
        log_hash = hashlib.sha256(log_result).hexdigest()
        rept_stream = json.dumps(cape_report).encode("utf8")
        rept_hash = hashlib.sha256(rept_stream).hexdigest()

        result = self.do_execution(
            data_in=[("content", data)],
            config={"cape_server": "http://dummy/", "poll_interval": 1},
            no_multiprocessing=True,
        )

        assert log_hash in result.data
        assert result.data[log_hash].read() == log_result
        assert rept_hash in result.data
        assert result.data[rept_hash].read() == rept_stream
        result.data.clear()  # Erase the data from result, as the BufferedRandom can't be easily compared

        # Read the expected features, in the format of {feat_name: [(value, label), ...], ...}
        #  and convert them to {feat_name: [FV(value, label), ...], ...}
        # Done this way because literal_eval will parse only direct literals, and not class instantiations
        expected_features = {
            feat_name: [FV(f_val, label=f_label) for (f_val, f_label) in feat_val_list]
            for feat_name, feat_val_list in ast.literal_eval(
                self.load_local_raw(
                    "u_cheatengine_expected_features.txt",
                    description="Expected features from the cheat engine executable that should come out of cape.",
                ).decode("utf8")
            ).items()
        }

        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id=hashlib.sha256(data).hexdigest(),
                        data=[
                            EventData(hash=log_hash, label="text"),
                            EventData(hash=rept_hash, label=DataLabel.CAPE_REPORT),
                        ],
                        features=expected_features,
                        info={
                            "CAPE_machine": "win7-test2",
                            "screenshot_hash": "",
                            "screenshot_count": 0,
                        },
                    ),
                ],
            ),
        )

    def test_already_in_cape(self):
        """Test a successful run where sample reports already being present in CAPE"""
        data = self.load_test_file_bytes(
            "8216f8d097740bcdaa1d0e9144e0e0afbc6e4c817b1cf15e8ae37244065cd129",
            "Cheat engine installer executable version 6.1.",
        )
        hook_http(self.mp, overrides={"/tasks/search/sha256/": {"error": 0, "data": [{"id": 1}]}})

        result = self.do_execution(
            data_in=[("content", data)],
            config={"cape_server": "http://dummy/", "poll_interval": 1},
            no_multiprocessing=True,
        )

        # This run should return a minimal result with no features except malscore
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id=hashlib.sha256(data).hexdigest(),
                        features={"cape_malscore": [FV(0.0)]},
                        data=[EventData(hash=dummy_report_hash, label=DataLabel.CAPE_REPORT)],
                        info={
                            "CAPE_machine": "TestCapeMachine",
                            "screenshot_hash": "",
                            "screenshot_count": 0,
                        },
                    ),
                ],
                data={dummy_report_hash: b""},
            ),
        )

    def test_multi_job_warning(self):
        """Test a for successful run with a warning if more than one matching job is found in CAPE"""
        data = self.load_test_file_bytes(
            "8216f8d097740bcdaa1d0e9144e0e0afbc6e4c817b1cf15e8ae37244065cd129",
            "Cheat engine installer executable version 6.1.",
        )
        hook_http(
            self.mp,
            overrides={
                "/tasks/search/sha256/": {"error": 0, "data": [{"id": 2}, {"id": 1}]},
                # Plugin should be using last job in list, so throw an error if it asks for job ID#1
                "/tasks/view/1": {"error": 1, "error_value": "Plugin asked for wrong job ID"},
            },
        )

        result = self.do_execution(
            data_in=[("content", data)],
            config={"cape_server": "http://dummy/", "poll_interval": 1},
            no_multiprocessing=True,
        )

        assert dummy_report_hash in result.data
        assert result.data[dummy_report_hash].read() == dummy_report_stream
        result.data.clear()
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id=hashlib.sha256(data).hexdigest(),
                        features={"cape_malscore": [FV(0.0)]},
                        data=[EventData(hash=dummy_report_hash, label=DataLabel.CAPE_REPORT)],
                        info={
                            "CAPE_machine": "TestCapeMachine",
                            "screenshot_hash": "",
                            "screenshot_count": 0,
                        },
                    ),
                ],
            ),
        )
        assert "More than one CAPE task found for this entity [2, 1]; using the first one" in self.caplog.text

    def test_cape_guest_name_missing(self):
        """Test for expected error when CAPE does not return the name of the guest VM"""
        data = self.load_test_file_bytes(
            "8216f8d097740bcdaa1d0e9144e0e0afbc6e4c817b1cf15e8ae37244065cd129",
            "Cheat engine installer executable version 6.1.",
        )
        hook_http(
            self.mp,
            overrides={
                "/tasks/get/report/": {
                    "error": 0,
                    "debug": {"log": ""},
                    "info": {},  # {"machine": {"name": "blah"}} is intentionally missing here
                    "malscore": 0.0,
                    "signatures": [],
                    "ttps": [],
                    "behavior": {
                        "summary": {
                            "read_files": [],
                            "write_files": [],
                            "delete_files": [],
                            "read_keys": [],
                            "write_keys": [],
                            "delete_keys": [],
                            "executed_commands": [],
                        },
                    },
                }
            },
        )

        result = self.do_execution(
            data_in=[("content", data)],
            config={"cape_server": "http://dummy/", "poll_interval": 1},
            no_multiprocessing=True,
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(
                    State.Label.ERROR_EXCEPTION,
                    failure_name="Cape guest machine name missing, assuming execution failed",
                )
            ),
        )

    def test_cape_search_error(self):
        """Test for expected error when checking if file is in CAPE"""
        data = self.load_test_file_bytes(
            "8216f8d097740bcdaa1d0e9144e0e0afbc6e4c817b1cf15e8ae37244065cd129",
            "Cheat engine installer executable version 6.1.",
        )
        hook_http(self.mp, overrides={"/tasks/search/sha256/": {"error": 1, "error_value": "Test error"}})

        result = self.do_execution(
            data_in=[("content", data)], config={"cape_server": "http://dummy/"}, no_multiprocessing=True
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(
                    State.Label.ERROR_EXCEPTION,
                    failure_name="CAPE returned error checking if file already present",
                    message="Test error",
                )
            ),
        )

    def test_cape_submit_error(self):
        """Test for expected error message when submission failed"""
        data = self.load_test_file_bytes(
            "8216f8d097740bcdaa1d0e9144e0e0afbc6e4c817b1cf15e8ae37244065cd129",
            "Cheat engine installer executable version 6.1.",
        )
        hook_http(self.mp, overrides={"/tasks/create/file/": {"error": 1, "error_value": "Test error"}})

        result = self.do_execution(
            data_in=[("content", data)],
            config={"cape_server": "http://dummy/", "poll_interval": 1},
            no_multiprocessing=True,
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(
                    State.Label.ERROR_EXCEPTION,
                    failure_name="CAPE returned error submitting job",
                    message="Test error",
                )
            ),
        )

    def test_cape_processing_timeout(self):
        """Test that plugin correctly reports error when CAPE doesn't start processing sample within time limit"""
        data = self.load_test_file_bytes(
            "8216f8d097740bcdaa1d0e9144e0e0afbc6e4c817b1cf15e8ae37244065cd129",
            "Cheat engine installer executable version 6.1.",
        )
        hook_http(
            self.mp,
            overrides={
                "/tasks/view/": {
                    "error": 0,
                    "data": {
                        "added_on": str(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1))[
                            :19
                        ]
                    },
                }
            },
        )

        result = self.do_execution(
            data_in=[("content", data)],
            config={"cape_server": "http://dummy/", "poll_interval": 1, "start_timeout": 600},
            no_multiprocessing=True,
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(
                    State.Label.ERROR_EXCEPTION,
                    failure_name="CAPE did not start processing within 600 seconds",
                )
            ),
        )

    def test_cape_processing_error(self):
        """Test for expected error message when CAPE returns a processing error"""
        data = self.load_test_file_bytes(
            "8216f8d097740bcdaa1d0e9144e0e0afbc6e4c817b1cf15e8ae37244065cd129",
            "Cheat engine installer executable version 6.1.",
        )
        hook_http(
            self.mp,
            overrides={
                "/tasks/status/": [
                    {"error": 0, "data": "pending"},
                    {"error": 0, "data": "running"},
                    {"error": 0, "data": "failed_processing"},
                ],
            },
        )

        result = self.do_execution(
            data_in=[("content", data)],
            config={"cape_server": "http://dummy/", "poll_interval": 1},
            no_multiprocessing=True,
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(
                    State.Label.ERROR_EXCEPTION,
                    failure_name="CAPE job error: failed_processing",
                )
            ),
        )

    def test_image_compare_reliable(self):
        """Test to ensure our image comparison returns success or fail as intended"""
        # This may be paranoid, but in case Pillow behaves unexpectedly we want to know that
        #  rather than dealing with unexplainable test failures (or passes when it shouldn't pass)
        webp_file = io.BytesIO()
        self._test_imgs[0].save(
            webp_file, format="WebP", quality=80, save_all=True, append_images=self._test_imgs[1:], duration=500
        )

        # Check they test as the same
        if _compare_img_seqs(self._test_imgs, webp_file.getvalue()) != True:
            raise RuntimeError("Test images failed to compare equal to WEBP file generated from them")
        # Check comparing with reversed sequence of test images tests as different
        if _compare_img_seqs(reversed(self._test_imgs), webp_file.getvalue()) != False:
            raise RuntimeError("Test images incorrectly compared equal to their reversal - investigate")

    def test_CAPE_screenshots_returned(self):
        """Test a job already in CAPE that has screenshots available"""
        data = self.load_test_file_bytes(
            "8216f8d097740bcdaa1d0e9144e0e0afbc6e4c817b1cf15e8ae37244065cd129",
            "Cheat engine installer executable version 6.1.",
        )
        hook_http(
            self.mp,
            overrides={
                "/tasks/search/sha256/": {"error": 0, "data": [{"id": 1}]},
                "/tasks/get/screenshot/": _make_img_zip(self._test_imgs),
            },
        )

        result = self.do_execution(
            data_in=[("content", data)],
            config={"cape_server": "http://dummy/", "poll_interval": 1},
            no_multiprocessing=True,
        )

        # This run should return a minimal result with no features except malscore, plus screenshots
        ss_hash = result.events[0].info["screenshot_hash"]
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id=hashlib.sha256(data).hexdigest(),
                        features={"cape_malscore": [FV(0.0)]},
                        data=[
                            EventData(hash=dummy_report_hash, label=DataLabel.CAPE_REPORT),
                            EventData(hash=ss_hash, label="screenshot"),
                        ],
                        info={
                            "CAPE_machine": "TestCapeMachine",
                            "screenshot_hash": ss_hash,
                            "screenshot_count": len(self._test_imgs),
                        },
                    ),
                ],
                data={dummy_report_hash: b"", ss_hash: b""},
            ),
        )
        # Make sure images are approximately equal
        self.assertTrue(_compare_img_seqs(self._test_imgs, result.data[ss_hash].read()))

    def test_CAPE_real_screenshots_zip(self):
        """Test a CAPE job with screenshots from a zip generated from a real sample run"""
        data = self.load_test_file_bytes(
            "8216f8d097740bcdaa1d0e9144e0e0afbc6e4c817b1cf15e8ae37244065cd129",
            "Cheat engine installer executable version 6.1.",
        )
        zip_file = self.load_local_raw(
            "u_cheatengine_screenshots.zip",
            description="Screenshot from cape when running the cheat engine executable.",
        )
        hook_http(
            self.mp,
            overrides={
                "/tasks/search/sha256/": {"error": 0, "data": [{"id": 1}]},
                "/tasks/get/screenshot/": zip_file,
            },
        )

        result = self.do_execution(
            data_in=[("content", data)],
            config={"cape_server": "http://dummy/", "poll_interval": 1},
            no_multiprocessing=True,
        )

        # Load expected
        with self._get_data("u_cheatengine_expected_result.webp") as webp_file:
            expected_webp = Image.open(webp_file)

        # This run should return a minimal result with no features except malscore, plus screenshots
        ss_hash = result.events[0].info["screenshot_hash"]
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id=hashlib.sha256(data).hexdigest(),
                        features={"cape_malscore": [FV(0.0)]},
                        data=[
                            EventData(hash=dummy_report_hash, label=DataLabel.CAPE_REPORT),
                            EventData(hash=ss_hash, label="screenshot"),
                        ],
                        info={
                            "CAPE_machine": "TestCapeMachine",
                            "screenshot_hash": ss_hash,
                            "screenshot_count": getattr(expected_webp, "n_frames", 1),
                        },
                    ),
                ],
                data={dummy_report_hash: b"", ss_hash: b""},
            ),
        )
        # Make sure images are approximately equal
        self.assertTrue(_compare_img_seqs(ImageSequence.Iterator(expected_webp), result.data[ss_hash].read()))

    def test_CAPE_screenshots_empty_zip(self):
        """Test that the plugin returns no screenshots if given an empty screenshot zip"""
        data = self.load_test_file_bytes(
            "8216f8d097740bcdaa1d0e9144e0e0afbc6e4c817b1cf15e8ae37244065cd129",
            "Cheat engine installer executable version 6.1.",
        )
        hook_http(
            self.mp,
            overrides={
                "/tasks/search/sha256/": {"error": 0, "data": [{"id": 1}]},
                "/tasks/get/screenshot/": _make_img_zip([]),  # Will produce a valid but empty zip
            },
        )

        result = self.do_execution(
            data_in=[("content", data)],
            config={"cape_server": "http://dummy/", "poll_interval": 1},
            no_multiprocessing=True,
        )

        # This run should return a minimal result with no features except malscore
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id=hashlib.sha256(data).hexdigest(),
                        features={"cape_malscore": [FV(0.0)]},
                        data=[EventData(hash=dummy_report_hash, label=DataLabel.CAPE_REPORT)],
                        info={
                            "CAPE_machine": "TestCapeMachine",
                            "screenshot_hash": "",
                            "screenshot_count": 0,
                        },
                    ),
                ],
                data={dummy_report_hash: b""},
            ),
        )
        # Plugin should have emitted a warning about empty zip
        self.assertIn(
            "CAPE returned an empty screenshot zip; treating as no screenshots exist",
            self.caplog.text,
        )

    def test_CAPE_screenshots_error(self):
        """Test that fetching screenshots still returns an error for a response code error other than 500"""
        data = self.load_test_file_bytes(
            "8216f8d097740bcdaa1d0e9144e0e0afbc6e4c817b1cf15e8ae37244065cd129",
            "Cheat engine installer executable version 6.1.",
        )
        hook_http(
            self.mp,
            overrides={
                "/tasks/search/sha256/": {"error": 0, "data": [{"id": 1}]},
                "/tasks/get/screenshot/": httpx.Response(403),
            },
        )

        result = self.do_execution(
            data_in=[("content", data)],
            config={"cape_server": "http://dummy/", "poll_interval": 1},
            no_multiprocessing=True,
        )

        # This run should return an error result
        self.assertJobResult(
            result,
            JobResult(
                state=State(
                    State.Label.ERROR_EXCEPTION,
                    failure_name="HTTPStatusError",
                    message=result.state.message,  # Checked with assertion below
                )
            ),
        )
        self.assertIn(
            "HTTPStatusError: Client error '403 Forbidden' for url 'http://dummy//apiv2/tasks/get/screenshot/1/'",
            result.state.message,
        )
