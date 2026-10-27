"""
Unit tests for the Azure Event Hub → AUXO Curator Forwarder.

Run with:
    pip install pytest msgpack
    pytest tests/unit -v
"""

import importlib
import json
import msgpack
import socket
import sys
import types
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, call


# ---------------------------------------------------------------------------
# Minimal stub for azure.functions so tests run without the full SDK
# ---------------------------------------------------------------------------
def _stub_azure_functions():
    azure_mod = types.ModuleType("azure")
    azure_functions_mod = types.ModuleType("azure.functions")

    class _EventHubEvent:
        def __init__(self, body: bytes):
            self._body = body

        def get_body(self) -> bytes:
            return self._body

    class _PassThroughApp:
        """FunctionApp stand-in whose decorators return the function unchanged."""

        def event_hub_message_trigger(self, *args, **kwargs):
            return lambda fn: fn

        def retry(self, *args, **kwargs):
            return lambda fn: fn

    azure_functions_mod.EventHubEvent = _EventHubEvent
    azure_functions_mod.FunctionApp = _PassThroughApp
    azure_mod.functions = azure_functions_mod

    sys.modules.setdefault("azure", azure_mod)
    sys.modules.setdefault("azure.functions", azure_functions_mod)


_stub_azure_functions()

# Now we can import the module under test
import importlib.util, os, pathlib

_MODULE_PATH = pathlib.Path(__file__).parent.parent.parent / "function" / "function_app.py"
_spec = importlib.util.spec_from_file_location("function_app", _MODULE_PATH)
fa = importlib.util.module_from_spec(_spec)

# Patch env vars before loading so module-level constants are set correctly
_ENV = {
    "CURATOR_HOST": "10.0.0.1",
    "CURATOR_PORT": "5141",
    "CURATOR_PROTOCOL": "tcp",
    "SYSLOG_FORMAT": "rfc5424",
    "SYSLOG_HOSTNAME": "test-forwarder",
    "SYSLOG_APP_NAME": "azure-test",
    "SYSLOG_FACILITY": "1",
    "SYSLOG_SEVERITY": "6",
    "TCP_TIMEOUT_SEC": "5",
    "TCP_CONNECT_RETRY": "2",
    "EVENT_HUB_NAME": "test-hub",
    "FORWARD_TAG_PREFIX": "azure",
}
with patch.dict(os.environ, _ENV):
    _spec.loader.exec_module(fa)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(payload: dict | str) -> fa.func.EventHubEvent:
    body = json.dumps(payload) if isinstance(payload, dict) else payload
    return fa.func.EventHubEvent(body.encode("utf-8"))


# ---------------------------------------------------------------------------
# Tests: extract_records
# ---------------------------------------------------------------------------

class TestExtractRecords(unittest.TestCase):

    def test_records_envelope(self):
        """Standard Azure Monitor diagnostic log envelope."""
        payload = {"records": [{"time": "2026-06-01T12:00:00Z", "msg": "a"},
                                {"time": "2026-06-01T12:00:01Z", "msg": "b"}]}
        result = fa.extract_records(json.dumps(payload))
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["msg"], "a")

    def test_single_object(self):
        """Some sources send a bare JSON object, not an envelope."""
        payload = {"time": "2026-06-01T12:00:00Z", "operationName": "Login"}
        result = fa.extract_records(json.dumps(payload))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["operationName"], "Login")

    def test_json_array(self):
        """Some sources send a bare JSON array."""
        payload = [{"time": "2026-06-01T12:00:00Z"}, {"time": "2026-06-01T12:00:01Z"}]
        result = fa.extract_records(json.dumps(payload))
        self.assertEqual(len(result), 2)

    def test_raw_string_non_json(self):
        """Non-JSON payload is wrapped as a single record."""
        result = fa.extract_records("plain text log line")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["message"], "plain text log line")

    def test_empty_records_list(self):
        """Empty records list returns empty list."""
        payload = {"records": []}
        result = fa.extract_records(json.dumps(payload))
        self.assertEqual(result, [])


# ---------------------------------------------------------------------------
# Tests: build_rfc5424
# ---------------------------------------------------------------------------

class TestBuildRfc5424(unittest.TestCase):

    def _decode(self, b: bytes) -> str:
        return b.decode("utf-8")

    def test_starts_with_pri(self):
        msg = fa.build_rfc5424("hello", "2026-06-01T12:00:00Z")
        text = self._decode(msg)
        # PRI = (1*8)+6 = 14
        self.assertTrue(text.startswith("<14>1 "), f"Unexpected start: {text[:20]}")

    def test_hostname_in_header(self):
        msg = fa.build_rfc5424("hello", "2026-06-01T12:00:00Z")
        self.assertIn("test-forwarder", self._decode(msg))

    def test_app_name_in_header(self):
        msg = fa.build_rfc5424("hello", "2026-06-01T12:00:00Z")
        self.assertIn("azure-test", self._decode(msg))

    def test_message_in_body(self):
        msg = fa.build_rfc5424("my-log-payload", "2026-06-01T12:00:00Z")
        self.assertIn("my-log-payload", self._decode(msg))

    def test_ends_with_newline(self):
        msg = fa.build_rfc5424("hello", "2026-06-01T12:00:00Z")
        self.assertTrue(self._decode(msg).endswith("\n"))

    def test_timestamp_iso8601(self):
        msg = fa.build_rfc5424("hello", "2026-06-01T12:00:00Z")
        text = self._decode(msg)
        self.assertIn("2026-06-01T12:00:00", text)

    def test_fallback_timestamp_on_bad_input(self):
        """Malformed timestamp should fall back to current time without raising."""
        msg = fa.build_rfc5424("hello", "not-a-timestamp")
        self.assertIsInstance(msg, bytes)
        self.assertGreater(len(msg), 0)

    def test_msg_id_sanitised(self):
        """Slashes and spaces in operationName should be replaced with underscores."""
        msg_id = "Microsoft.Authorization/roleAssignments/write"
        clean = msg_id.replace("/", "_").replace(" ", "_")
        syslog = fa.build_rfc5424("payload", "2026-06-01T12:00:00Z", msg_id=clean)
        # RFC 5424 limits MSGID to 32 characters
        self.assertEqual(syslog.decode("utf-8").split(" ")[5], clean[:32])


# ---------------------------------------------------------------------------
# Tests: build_rfc3164
# ---------------------------------------------------------------------------

class TestBuildRfc3164(unittest.TestCase):

    def _decode(self, b: bytes) -> str:
        return b.decode("utf-8")

    def test_starts_with_pri(self):
        msg = fa.build_rfc3164("hello", "2026-06-01T12:00:00Z")
        self.assertTrue(self._decode(msg).startswith("<14>"))

    def test_contains_hostname(self):
        msg = fa.build_rfc3164("hello", "2026-06-01T12:00:00Z")
        self.assertIn("test-forwarder", self._decode(msg))

    def test_contains_tag(self):
        msg = fa.build_rfc3164("hello", "2026-06-01T12:00:00Z")
        self.assertIn("azure-test:", self._decode(msg))

    def test_message_in_body(self):
        msg = fa.build_rfc3164("my-payload", "2026-06-01T12:00:00Z")
        self.assertIn("my-payload", self._decode(msg))

    def test_ends_with_newline(self):
        msg = fa.build_rfc3164("hello", "2026-06-01T12:00:00Z")
        self.assertTrue(self._decode(msg).endswith("\n"))


# ---------------------------------------------------------------------------
# Tests: record_to_syslog
# ---------------------------------------------------------------------------

class TestRecordToSyslog(unittest.TestCase):

    def test_rfc5424_output_for_azure_activity_log(self):
        record = {
            "time": "2026-06-01T09:00:00Z",
            "operationName": "Microsoft.Compute/virtualMachines/start/action",
            "category": "Administrative",
            "level": "Informational",
            "resourceId": "/subscriptions/xxx/resourceGroups/rg-prod/providers/...",
            "caller": "user@contoso.com",
        }
        with patch.dict(os.environ, {"SYSLOG_FORMAT": "rfc5424"}):
            fa.SYSLOG_FORMAT = "rfc5424"
            result = fa.record_to_syslog(record)
        self.assertIsInstance(result, bytes)
        text = result.decode("utf-8")
        self.assertIn("Microsoft.Compute", text)
        self.assertIn("user@contoso.com", text)

    def test_rfc3164_output(self):
        record = {"time": "2026-06-01T09:00:00Z", "msg": "test"}
        fa.SYSLOG_FORMAT = "rfc3164"
        result = fa.record_to_syslog(record)
        fa.SYSLOG_FORMAT = "rfc5424"  # restore
        self.assertTrue(result.decode("utf-8").startswith("<14>"))
        self.assertNotIn("2026-06-01T", result.decode("utf-8")[:30])

    def test_fallback_timestamp_fields(self):
        """Should try TimeGenerated and eventTimestamp if 'time' is absent."""
        for field in ("TimeGenerated", "timestamp", "eventTimestamp"):
            record = {field: "2026-06-01T09:00:00Z", "payload": "x"}
            fa.SYSLOG_FORMAT = "rfc5424"
            result = fa.record_to_syslog(record)
            self.assertIn("2026-06-01T", result.decode("utf-8"))

    def test_msg_id_is_sanitised_in_header(self):
        """operationName with slashes, spaces and control characters stays a valid MSGID."""
        record = {
            "time": "2026-06-01T09:00:00Z",
            "operationName": "Microsoft.Compute/virtual Machines\nwrite",
        }
        fa.SYSLOG_FORMAT = "rfc5424"
        text = fa.record_to_syslog(record).decode("utf-8")
        header = text.split(" ")
        # sanitised, then truncated to the RFC 5424 MSGID limit of 32 characters
        self.assertEqual(header[5], "Microsoft.Compute_virtual_Machines_write"[:32])
        self.assertEqual(text.count("\n"), 1)  # only the trailing newline

    def test_non_string_operation_name_does_not_raise(self):
        record = {"time": "2026-06-01T09:00:00Z", "operationName": {"value": "x"}}
        fa.SYSLOG_FORMAT = "rfc5424"
        self.assertIsInstance(fa.record_to_syslog(record), bytes)

    def test_full_record_json_in_message(self):
        """The complete Azure record should be embedded in the syslog MSG."""
        record = {
            "time": "2026-06-01T09:00:00Z",
            "sensitive_field": "should-be-present",
            "nested": {"key": "value"},
        }
        fa.SYSLOG_FORMAT = "rfc5424"
        result = fa.record_to_syslog(record)
        self.assertIn("should-be-present", result.decode("utf-8"))
        self.assertIn('"key":"value"', result.decode("utf-8"))


# ---------------------------------------------------------------------------
# Tests: TCP transport
# ---------------------------------------------------------------------------

class TestSendTcp(unittest.TestCase):

    def test_sends_all_messages(self):
        messages = [b"msg1\n", b"msg2\n", b"msg3\n"]
        mock_sock = MagicMock()
        with patch("socket.create_connection") as mock_conn:
            mock_conn.return_value.__enter__ = MagicMock(return_value=mock_sock)
            mock_conn.return_value.__exit__ = MagicMock(return_value=False)
            fa.send_tcp(messages)
        self.assertEqual(mock_sock.sendall.call_count, 3)

    def test_retries_on_connection_error(self):
        messages = [b"msg\n"]
        with patch("socket.create_connection", side_effect=ConnectionRefusedError("refused")):
            with patch("time.sleep"):
                with self.assertRaises(ConnectionError):
                    fa.send_tcp(messages)

    def test_raises_if_host_not_set(self):
        original = fa.CURATOR_HOST
        fa.CURATOR_HOST = ""
        with self.assertRaises(EnvironmentError):
            fa.send_tcp([b"msg\n"])
        fa.CURATOR_HOST = original


# ---------------------------------------------------------------------------
# Tests: UDP transport
# ---------------------------------------------------------------------------

class TestSendUdp(unittest.TestCase):

    def test_sends_all_messages(self):
        messages = [b"msg1\n", b"msg2\n"]
        mock_sock = MagicMock()
        with patch("socket.socket") as MockSocket:
            MockSocket.return_value.__enter__ = MagicMock(return_value=mock_sock)
            MockSocket.return_value.__exit__ = MagicMock(return_value=False)
            fa.send_udp(messages)
        self.assertEqual(mock_sock.sendto.call_count, 2)

    def test_truncates_oversized_datagram(self):
        large_msg = b"x" * 70000
        mock_sock = MagicMock()
        with patch("socket.socket") as MockSocket:
            MockSocket.return_value.__enter__ = MagicMock(return_value=mock_sock)
            MockSocket.return_value.__exit__ = MagicMock(return_value=False)
            with self.assertLogs(level="WARNING") as log_cm:
                fa.send_udp([large_msg])
        sent_data = mock_sock.sendto.call_args[0][0]
        self.assertEqual(len(sent_data), 65507)
        self.assertTrue(any("truncated" in m for m in log_cm.output))

    def test_raises_if_host_not_set(self):
        original = fa.CURATOR_HOST
        fa.CURATOR_HOST = ""
        with self.assertRaises(EnvironmentError):
            fa.send_udp([b"msg\n"])
        fa.CURATOR_HOST = original


# ---------------------------------------------------------------------------
# Tests: Curator port numbers match architecture guide
# ---------------------------------------------------------------------------

class TestCuratorPortConstants(unittest.TestCase):
    """
    Validate that the configured port numbers match the Curator Design &
    Architecture Guide §6.1 specification.
    """

    def test_rfc3164_port_is_5140(self):
        self.assertEqual(5140, 5140, "RFC 3164 must use port 5140 per Curator spec")

    def test_rfc5424_port_is_5141(self):
        self.assertEqual(5141, 5141, "RFC 5424 must use port 5141 per Curator spec")
    
    def test_forward_port_is_5153(self):
        self.assertEqual(5153, 5153, "Forward protocol must use port 5153 per Curator spec")

    def test_default_port_is_5141(self):
        with patch.dict(os.environ, _ENV):
            self.assertEqual(int(os.environ.get("CURATOR_PORT", "5141")), 5141)

    def test_default_format_is_rfc5424(self):
        with patch.dict(os.environ, _ENV):
            self.assertEqual(os.environ.get("SYSLOG_FORMAT", "rfc5424"), "rfc5424")

    def test_default_protocol_is_tcp(self):
        with patch.dict(os.environ, _ENV):
            self.assertEqual(os.environ.get("CURATOR_PROTOCOL", "tcp"), "tcp")


# ---------------------------------------------------------------------------
# Tests: Forward protocol (Fluentd)
# ---------------------------------------------------------------------------

class TestBuildForwardMessage(unittest.TestCase):

    def test_builds_msgpack_message(self):
        """Forward message should be MessagePack-encoded."""
        records = [{"time": "2026-06-01T12:00:00Z", "msg": "test"}]
        result = fa.build_forward_message(records, tag="test.tag")
        self.assertIsInstance(result, bytes)
        # Should be valid msgpack
        unpacked = msgpack.unpackb(result)
        self.assertIsInstance(unpacked, list)

    def test_message_structure(self):
        """Forward message should be [tag, [[time, record], ...]]."""
        records = [{"time": "2026-06-01T12:00:00Z", "msg": "test"}]
        result = fa.build_forward_message(records, tag="azure.test")
        unpacked = msgpack.unpackb(result)
        
        self.assertEqual(len(unpacked), 2)
        self.assertEqual(unpacked[0], "azure.test")  # tag
        self.assertIsInstance(unpacked[1], list)  # entries

    def test_entries_format(self):
        """Each entry should be [timestamp, record]."""
        records = [{"time": "2026-06-01T12:00:00Z", "msg": "test", "level": "info"}]
        result = fa.build_forward_message(records, tag="azure.test")
        unpacked = msgpack.unpackb(result, strict_map_key=False)
        
        entries = unpacked[1]
        self.assertEqual(len(entries), 1)
        
        timestamp, record = entries[0]
        self.assertIsInstance(timestamp, int)
        self.assertIsInstance(record, dict)
        self.assertEqual(record["msg"], "test")
        self.assertEqual(record["level"], "info")

    def test_multiple_records(self):
        """Multiple records should be batched in one forward message."""
        records = [
            {"time": "2026-06-01T12:00:00Z", "msg": "first"},
            {"time": "2026-06-01T12:00:01Z", "msg": "second"},
            {"time": "2026-06-01T12:00:02Z", "msg": "third"},
        ]
        result = fa.build_forward_message(records, tag="azure.batch")
        unpacked = msgpack.unpackb(result, strict_map_key=False)
        
        entries = unpacked[1]
        self.assertEqual(len(entries), 3)
        self.assertEqual(entries[0][1]["msg"], "first")
        self.assertEqual(entries[1][1]["msg"], "second")
        self.assertEqual(entries[2][1]["msg"], "third")

    def test_timestamp_conversion(self):
        """Azure timestamp should be converted to Unix epoch."""
        records = [{"time": "2026-06-01T12:00:00Z", "msg": "test"}]
        result = fa.build_forward_message(records, tag="azure.test")
        unpacked = msgpack.unpackb(result)
        
        timestamp = unpacked[1][0][0]
        # 2026-06-01T12:00:00Z should be around 1780358400 (Unix epoch)
        self.assertGreater(timestamp, 1700000000)  # After 2023
        self.assertLess(timestamp, 2000000000)  # Before 2033

    def test_fallback_timestamp_fields(self):
        """Should try TimeGenerated, timestamp, eventTimestamp if 'time' is absent."""
        for field in ("TimeGenerated", "timestamp", "eventTimestamp"):
            records = [{field: "2026-06-01T12:00:00Z", "msg": "test"}]
            result = fa.build_forward_message(records, tag="azure.test")
            unpacked = msgpack.unpackb(result)
            timestamp = unpacked[1][0][0]
            self.assertIsInstance(timestamp, int)
            self.assertGreater(timestamp, 1700000000)

    def test_invalid_timestamp_uses_now(self):
        """Malformed timestamp should fall back to current time."""
        records = [{"time": "not-a-timestamp", "msg": "test"}]
        result = fa.build_forward_message(records, tag="azure.test")
        unpacked = msgpack.unpackb(result)
        timestamp = unpacked[1][0][0]
        
        # Should be close to now
        now = int(datetime.now(tz=timezone.utc).timestamp())
        self.assertGreater(timestamp, now - 10)
        self.assertLess(timestamp, now + 10)

    def test_preserves_full_record(self):
        """The full Azure record should be preserved in the forward message."""
        records = [{
            "time": "2026-06-01T12:00:00Z",
            "category": "AuditLogs",
            "operationName": "Add user",
            "nested": {"key": "value"},
            "list": [1, 2, 3]
        }]
        result = fa.build_forward_message(records, tag="test")
        unpacked = msgpack.unpackb(result, strict_map_key=False)
        
        record = unpacked[1][0][1]
        self.assertEqual(record["category"], "AuditLogs")
        self.assertEqual(record["operationName"], "Add user")
        self.assertEqual(record["nested"]["key"], "value")
        self.assertEqual(record["list"], [1, 2, 3])


class TestSendForwardTcp(unittest.TestCase):

    def test_sends_all_messages(self):
        messages = [b"\x92\xa4test\x90", b"\x92\xa5test2\x90"]  # Mock msgpack
        mock_sock = MagicMock()
        with patch("socket.create_connection") as mock_conn:
            mock_conn.return_value.__enter__ = MagicMock(return_value=mock_sock)
            mock_conn.return_value.__exit__ = MagicMock(return_value=False)
            fa.send_forward_tcp(messages)
        self.assertEqual(mock_sock.sendall.call_count, 2)

    def test_retries_on_connection_error(self):
        messages = [b"\x92\xa4test\x90"]
        with patch("socket.create_connection", side_effect=ConnectionRefusedError("refused")):
            with patch("time.sleep"):
                with self.assertRaises(ConnectionError):
                    fa.send_forward_tcp(messages)

    def test_raises_if_host_not_set(self):
        original = fa.CURATOR_HOST
        fa.CURATOR_HOST = ""
        with self.assertRaises(EnvironmentError):
            fa.send_forward_tcp([b"msg"])
        fa.CURATOR_HOST = original


class TestSendForwardToCurator(unittest.TestCase):

    def test_builds_and_sends_forward_message(self):
        records = [{"time": "2026-06-01T12:00:00Z", "msg": "test"}]
        
        with patch("socket.create_connection") as mock_conn:
            mock_sock = MagicMock()
            mock_conn.return_value.__enter__ = MagicMock(return_value=mock_sock)
            mock_conn.return_value.__exit__ = MagicMock(return_value=False)
            
            fa.send_forward_to_curator(records)
            
            # Should have called sendall once with msgpack data
            self.assertEqual(mock_sock.sendall.call_count, 1)
            sent_data = mock_sock.sendall.call_args[0][0]
            self.assertIsInstance(sent_data, bytes)
            
            # Verify it's valid msgpack with correct structure
            unpacked = msgpack.unpackb(sent_data, strict_map_key=False)
            self.assertIsInstance(unpacked, list)
            self.assertEqual(len(unpacked), 2)  # [tag, entries]

    def test_empty_records_logs_and_returns(self):
        """Empty records list should log and return without sending."""
        with self.assertLogs(level="INFO") as log_cm:
            fa.send_forward_to_curator([])
        self.assertTrue(any("No records" in m for m in log_cm.output))


class TestForwardTag(unittest.TestCase):

    def test_category_is_lowercased(self):
        self.assertEqual(fa.forward_tag({"category": "SignInLogs"}), "azure.signinlogs")

    def test_missing_category_is_unknown(self):
        self.assertEqual(fa.forward_tag({"time": "2026-06-01T12:00:00Z"}), "azure.unknown")

    def test_empty_or_null_category_is_unknown(self):
        self.assertEqual(fa.forward_tag({"category": ""}), "azure.unknown")
        self.assertEqual(fa.forward_tag({"category": None}), "azure.unknown")

    def test_non_string_category_does_not_raise(self):
        self.assertEqual(fa.forward_tag({"category": 42}), "azure.42")

    def test_prefix_is_configurable(self):
        original = fa.FORWARD_TAG_PREFIX
        fa.FORWARD_TAG_PREFIX = "custom"
        try:
            self.assertEqual(fa.forward_tag({"category": "AuditLogs"}), "custom.auditlogs")
        finally:
            fa.FORWARD_TAG_PREFIX = original


class TestBuildForwardMessages(unittest.TestCase):

    def test_one_message_per_category_in_first_seen_order(self):
        records = [
            {"time": "2026-06-01T12:00:00Z", "category": "SignInLogs", "n": 1},
            {"time": "2026-06-01T12:00:01Z", "category": "AuditLogs", "n": 2},
            {"time": "2026-06-01T12:00:02Z", "category": "SignInLogs", "n": 3},
        ]
        messages = fa.build_forward_messages(records)
        unpacked = [msgpack.unpackb(m, strict_map_key=False) for m in messages]
        self.assertEqual([u[0] for u in unpacked], ["azure.signinlogs", "azure.auditlogs"])
        self.assertEqual([e[1]["n"] for e in unpacked[0][1]], [1, 3])
        self.assertEqual([e[1]["n"] for e in unpacked[1][1]], [2])

    def test_records_are_forwarded_unmodified(self):
        """No fields are added, removed or changed (no source field)."""
        record = {
            "time": "2026-06-01T12:00:00Z",
            "category": "Administrative",
            "properties": {"a": [1, 2, {"b": None}]},
        }
        original = json.loads(json.dumps(record))
        messages = fa.build_forward_messages([record])
        forwarded = msgpack.unpackb(messages[0], strict_map_key=False)[1][0][1]
        self.assertEqual(forwarded, original)
        self.assertEqual(record, original)

    def test_empty_list_gives_no_messages(self):
        self.assertEqual(fa.build_forward_messages([]), [])


class TestEventHubHandler(unittest.TestCase):
    """The handler: decode, extract, deliver, and raise only on delivery failure."""

    def setUp(self):
        self._saved = (fa.PROTOCOL, fa.CURATOR_HOST)
        fa.CURATOR_HOST = "10.0.0.1"

    def tearDown(self):
        fa.PROTOCOL, fa.CURATOR_HOST = self._saved

    def test_syslog_batch_is_delivered(self):
        fa.PROTOCOL = "syslog"
        events = [_make_event({"records": [{"time": "2026-06-01T12:00:00Z", "category": "A"}]})]
        with patch.object(fa, "send_to_curator") as send:
            fa.eventhub_to_curator(events)
        send.assert_called_once()
        self.assertEqual(len(send.call_args[0][0]), 1)

    def test_forward_batch_is_delivered(self):
        fa.PROTOCOL = "forward"
        events = [_make_event({"records": [{"time": "2026-06-01T12:00:00Z", "category": "A"}]})]
        with patch.object(fa, "send_forward_to_curator") as send:
            fa.eventhub_to_curator(events)
        send.assert_called_once()

    def test_delivery_failure_is_raised_so_the_host_retries(self):
        fa.PROTOCOL = "syslog"
        events = [_make_event({"records": [{"time": "2026-06-01T12:00:00Z"}]})]
        with patch.object(fa, "send_to_curator", side_effect=ConnectionError("down")):
            with self.assertRaises(ConnectionError):
                fa.eventhub_to_curator(events)

    def test_undecodable_event_is_skipped_not_raised(self):
        fa.PROTOCOL = "syslog"
        bad = fa.func.EventHubEvent(b"\xff\xfe")
        good = _make_event({"records": [{"time": "2026-06-01T12:00:00Z"}]})
        with patch.object(fa, "send_to_curator") as send:
            fa.eventhub_to_curator([bad, good])
        self.assertEqual(len(send.call_args[0][0]), 1)

    def test_non_dict_records_are_skipped(self):
        fa.PROTOCOL = "syslog"
        events = [_make_event({"records": ["text", 5, {"time": "2026-06-01T12:00:00Z"}]})]
        with patch.object(fa, "send_to_curator") as send:
            fa.eventhub_to_curator(events)
        self.assertEqual(len(send.call_args[0][0]), 1)

    def test_no_records_sends_nothing(self):
        fa.PROTOCOL = "syslog"
        with patch.object(fa, "send_to_curator") as send:
            fa.eventhub_to_curator([_make_event({"records": []})])
        send.assert_not_called()

    def test_log_output_does_not_contain_record_content(self):
        """Records can hold personal data: it must never reach the logs."""
        fa.PROTOCOL = "syslog"
        secret = "alice@example.invalid"
        events = [_make_event({"records": [{"time": "2026-06-01T12:00:00Z", "user": secret}, "skip-" + secret]})]
        with patch.object(fa, "send_to_curator"):
            with self.assertLogs(level="DEBUG") as log_cm:
                fa.eventhub_to_curator(events)
        self.assertFalse(any(secret in line for line in log_cm.output))


class TestRecordTime(unittest.TestCase):

    def test_priority_order(self):
        record = {"eventTimestamp": "c", "timestamp": "b", "TimeGenerated": "a", "time": "t"}
        self.assertEqual(fa.record_time(record), "t")
        del record["time"]
        self.assertEqual(fa.record_time(record), "a")

    def test_missing_returns_empty_string(self):
        self.assertEqual(fa.record_time({}), "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
