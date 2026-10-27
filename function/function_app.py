"""
Azure Event Hub → AUXO Curator Forwarder
========================================
Triggered by Azure Event Hub messages and forwards logs to the AUXO™ Curator
appliance using syslog (RFC 3164/5424) or Fluentd forward protocol.

Delivery is fire-and-forget: a successful send means the bytes were written to
the socket, not that Curator accepted them. Curator's forward input is not
known to acknowledge, and syslog over TCP has no acknowledgement at all.
Records are forwarded unmodified.

Curator ingestion ports (non-standard):
  Port 5140  →  RFC 3164 syslog
  Port 5141  →  RFC 5424 syslog
  Port 5153  →  Fluentd forward protocol

Environment variables (configure in Function App Application Settings):
  CURATOR_HOST          Curator IP or FQDN                          (required)
  CURATOR_PORT          5140, 5141, or 5153                         (default: 5141)
  PROTOCOL              syslog or forward                           (default: syslog)
  CURATOR_PROTOCOL      tcp or udp (syslog only)                    (default: tcp)
  SYSLOG_FORMAT         rfc3164 or rfc5424 (syslog only)           (default: rfc5424)
  SYSLOG_HOSTNAME       Hostname written into the syslog header     (default: azure-eventhub-forwarder)
  SYSLOG_APP_NAME       APP-NAME field (RFC 5424) / tag (RFC 3164) (default: azure)
  SYSLOG_FACILITY       Syslog facility number 0-23                 (default: 1  = user-level)
  SYSLOG_SEVERITY       Syslog severity number 0-7                  (default: 6  = informational)
  FORWARD_TAG_PREFIX    Prefix of the forward tag, <prefix>.<category> (default: azure)
  TCP_TIMEOUT_SEC       TCP connection timeout in seconds           (default: 10)
  TCP_CONNECT_RETRY     Number of TCP connection attempts           (default: 3)
  EVENT_HUB_NAME        Event Hub name                              (required)
  EVENT_HUB_CONSUMER_GROUP  Event Hub consumer group name           (default: $Default)
"""

import azure.functions as func
import json
import logging
import msgpack
import os
import re
import socket
import time
from datetime import datetime, timezone
from typing import List, Dict, Any

app = func.FunctionApp()

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration — all sourced from environment variables at cold-start
# ---------------------------------------------------------------------------
CURATOR_HOST = os.environ.get("CURATOR_HOST", "")
CURATOR_PORT = int(os.environ.get("CURATOR_PORT", "5141"))
PROTOCOL = os.environ.get("PROTOCOL", "syslog").lower()  # syslog or forward
CURATOR_PROTOCOL = os.environ.get("CURATOR_PROTOCOL", "tcp").lower()
SYSLOG_FORMAT = os.environ.get("SYSLOG_FORMAT", "rfc5424").lower()
SYSLOG_HOSTNAME = os.environ.get("SYSLOG_HOSTNAME", "azure-eventhub-forwarder")
SYSLOG_APP_NAME = os.environ.get("SYSLOG_APP_NAME", "azure")
SYSLOG_FACILITY = int(os.environ.get("SYSLOG_FACILITY", "1"))   # 1 = user-level
SYSLOG_SEVERITY = int(os.environ.get("SYSLOG_SEVERITY", "6"))   # 6 = informational
FORWARD_TAG_PREFIX = os.environ.get("FORWARD_TAG_PREFIX", "azure")
TCP_TIMEOUT_SEC = int(os.environ.get("TCP_TIMEOUT_SEC", "10"))
TCP_CONNECT_RETRY = int(os.environ.get("TCP_CONNECT_RETRY", "3"))

# PRI value = (facility * 8) + severity
SYSLOG_PRI = (SYSLOG_FACILITY * 8) + SYSLOG_SEVERITY


# ---------------------------------------------------------------------------
# Record helpers
# ---------------------------------------------------------------------------

def record_time(record: Dict[str, Any]) -> str:
    """
    Return the first populated timestamp field of an Azure log record, trying
    the common field names in priority order. Returns "" when none is set.
    """
    return (
        record.get("time")
        or record.get("TimeGenerated")
        or record.get("timestamp")
        or record.get("eventTimestamp")
        or ""
    )


# ---------------------------------------------------------------------------
# Syslog message builders
# ---------------------------------------------------------------------------

def build_rfc3164(message: str, timestamp: str) -> bytes:
    """
    Build an RFC 3164 (BSD syslog) message.

    Format:
        <PRI>TIMESTAMP HOSTNAME TAG: MSG\\n

    The TIMESTAMP is in local-time Mmm DD HH:MM:SS format as required by the spec.
    We use the event timestamp from Azure when available, falling back to now().
    """
    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        dt = datetime.now(tz=timezone.utc)

    # RFC 3164 timestamp format — note: single space before single-digit day
    ts = dt.strftime("%b %d %H:%M:%S").replace("  ", " ")  # handle leading zero → space
    tag = SYSLOG_APP_NAME[:32]  # tag max 32 chars per RFC

    line = f"<{SYSLOG_PRI}>{ts} {SYSLOG_HOSTNAME} {tag}: {message}\n"
    return line.encode("utf-8")


def build_rfc5424(message: str, timestamp: str, msg_id: str = "-") -> bytes:
    """
    Build an RFC 5424 (structured syslog) message.

    Format:
        <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG\\n

    We populate STRUCTURED-DATA (-) as Curator accepts any log format and
    does not require specific SD elements for Azure logs. The full Azure JSON
    payload is placed in the MSG field so Curator stores it verbatim.
    """
    version = 1
    proc_id = "-"
    structured_data = "-"

    # RFC 5424 requires ISO 8601 timestamp with timezone
    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        ts = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    except (ValueError, AttributeError):
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    app_name = SYSLOG_APP_NAME[:48]  # max 48 chars per RFC
    hostname = SYSLOG_HOSTNAME[:255]  # max 255 chars per RFC
    safe_msg_id = (msg_id[:32] if msg_id else "-")  # max 32 chars per RFC

    header = (
        f"<{SYSLOG_PRI}>{version} {ts} {hostname} "
        f"{app_name} {proc_id} {safe_msg_id} {structured_data} "
    )
    line = header + message + "\n"
    return line.encode("utf-8")


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------

def send_tcp(messages: List[bytes]) -> None:
    """
    Send syslog messages over TCP with retry logic.
    Opens one connection per batch to avoid holding idle connections across
    Function invocations (stateless execution model).

    Returning normally means the bytes were written to the socket. Curator's
    acceptance is not confirmed (syslog over TCP has no acknowledgement).
    """
    if not CURATOR_HOST:
        raise EnvironmentError("CURATOR_HOST is not configured.")

    last_exc = None
    for attempt in range(1, TCP_CONNECT_RETRY + 1):
        try:
            with socket.create_connection(
                (CURATOR_HOST, CURATOR_PORT), timeout=TCP_TIMEOUT_SEC
            ) as sock:
                for msg in messages:
                    sock.sendall(msg)
            logger.info(
                "Wrote %d syslog messages to %s:%d via TCP (delivery not confirmed)",
                len(messages), CURATOR_HOST, CURATOR_PORT
            )
            return
        except (socket.timeout, ConnectionRefusedError, OSError) as exc:
            last_exc = exc
            logger.warning(
                "TCP attempt %d/%d to %s:%d failed: %s",
                attempt, TCP_CONNECT_RETRY, CURATOR_HOST, CURATOR_PORT, exc
            )
            if attempt < TCP_CONNECT_RETRY:
                time.sleep(1 * attempt)  # simple linear back-off

    raise ConnectionError(
        f"Failed to deliver syslog messages to {CURATOR_HOST}:{CURATOR_PORT} "
        f"after {TCP_CONNECT_RETRY} attempts: {last_exc}"
    )


def send_udp(messages: List[bytes]) -> None:
    """
    Send syslog messages over UDP (fire-and-forget; no delivery guarantee).
    RFC 3164 historically used UDP/514; Curator uses non-standard ports.
    UDP datagrams are limited to 65507 bytes — large Azure payloads may be
    truncated. Prefer TCP in production environments.
    """
    if not CURATOR_HOST:
        raise EnvironmentError("CURATOR_HOST is not configured.")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for msg in messages:
            if len(msg) > 65507:
                logger.warning(
                    "UDP datagram truncated from %d to 65507 bytes. "
                    "Consider switching to TCP (CURATOR_PROTOCOL=tcp).",
                    len(msg)
                )
                msg = msg[:65507]
            sock.sendto(msg, (CURATOR_HOST, CURATOR_PORT))

    logger.info(
        "Sent %d syslog messages to %s:%d via UDP",
        len(messages), CURATOR_HOST, CURATOR_PORT
    )


def send_to_curator(messages: List[bytes]) -> None:
    """Route to TCP or UDP sender based on CURATOR_PROTOCOL setting."""
    if CURATOR_PROTOCOL == "udp":
        send_udp(messages)
    else:
        send_tcp(messages)


# ---------------------------------------------------------------------------
# Forward protocol (Fluentd)
# ---------------------------------------------------------------------------

def forward_tag(record: Dict[str, Any]) -> str:
    """
    Forward tag for a record: <FORWARD_TAG_PREFIX>.<category lowercased>.
    Records without a category use "unknown".
    """
    category = record.get("category")
    category = str(category).lower() if category else ""
    return f"{FORWARD_TAG_PREFIX}.{category or 'unknown'}"


def build_forward_message(records: List[Dict[str, Any]], tag: str) -> bytes:
    """
    Build a Fluentd forward protocol message (MessagePack format).

    The Fluentd forward protocol uses MessagePack to encode messages in the format:
        [tag, [[timestamp, record], [timestamp, record], ...]]

    Where:
    - tag: A string identifier for the log source (e.g., "azure.signinlogs")
    - timestamp: Unix epoch timestamp (integer seconds)
    - record: A dict containing the log data, unmodified

    Args:
        records: List of Azure log record dicts
        tag: Tag for the forward message

    Returns:
        MessagePack-encoded bytes ready to send over TCP
    """
    entries = []
    for record in records:
        # Convert the Azure timestamp to Unix epoch
        try:
            dt = datetime.fromisoformat(record_time(record).replace("Z", "+00:00"))
            timestamp = int(dt.timestamp())
        except (ValueError, AttributeError):
            timestamp = int(datetime.now(tz=timezone.utc).timestamp())

        # The record itself is the full Azure log entry
        entries.append([timestamp, record])

    # Fluentd forward protocol format: [tag, [[time, record], [time, record], ...]]
    message = [tag, entries]
    return msgpack.packb(message)


def build_forward_messages(records: List[Dict[str, Any]]) -> List[bytes]:
    """
    Group records by forward tag and build one forward message per tag, in the
    order each tag was first seen.
    """
    by_tag: Dict[str, List[Dict[str, Any]]] = {}
    for record in records:
        by_tag.setdefault(forward_tag(record), []).append(record)
    return [build_forward_message(group, tag) for tag, group in by_tag.items()]


def send_forward_tcp(messages: List[bytes]) -> None:
    """
    Send Fluentd forward protocol messages over TCP.

    Opens one connection per batch and sends all MessagePack-encoded messages.
    The forward protocol always uses TCP (no UDP variant).

    Fire-and-forget: no "chunk" option is set and no reply is read, so
    returning normally means the bytes were written to the socket.
    """
    if not CURATOR_HOST:
        raise EnvironmentError("CURATOR_HOST is not configured.")

    last_exc = None
    for attempt in range(1, TCP_CONNECT_RETRY + 1):
        try:
            with socket.create_connection(
                (CURATOR_HOST, CURATOR_PORT), timeout=TCP_TIMEOUT_SEC
            ) as sock:
                for msg in messages:
                    sock.sendall(msg)
            logger.info(
                "Wrote %d forward messages to %s:%d via TCP (delivery not confirmed)",
                len(messages), CURATOR_HOST, CURATOR_PORT
            )
            return
        except (socket.timeout, ConnectionRefusedError, OSError) as exc:
            last_exc = exc
            logger.warning(
                "TCP attempt %d/%d to %s:%d failed: %s",
                attempt, TCP_CONNECT_RETRY, CURATOR_HOST, CURATOR_PORT, exc
            )
            if attempt < TCP_CONNECT_RETRY:
                time.sleep(1 * attempt)  # simple linear back-off

    raise ConnectionError(
        f"Failed to deliver forward messages to {CURATOR_HOST}:{CURATOR_PORT} "
        f"after {TCP_CONNECT_RETRY} attempts: {last_exc}"
    )


def send_forward_to_curator(records: List[Dict[str, Any]]) -> None:
    """
    Send records to Curator using Fluentd forward protocol.

    Records are grouped per category tag (one forward message per tag) and all
    messages are sent over a single TCP connection.
    """
    if not records:
        logger.info("No records to send in this batch.")
        return

    messages = build_forward_messages(records)

    logger.info(
        "Forwarding batch of %d records in %d forward messages to Curator at %s:%d (forward protocol, TCP)",
        len(records),
        len(messages),
        CURATOR_HOST,
        CURATOR_PORT,
    )

    send_forward_tcp(messages)


# ---------------------------------------------------------------------------
# Azure log record processing
# ---------------------------------------------------------------------------

def extract_records(event_body: str) -> List[dict]:
    """
    Azure Event Hub messages from Azure Monitor Diagnostic Settings arrive
    as a JSON envelope:

        { "records": [ { ...log entry... }, { ...log entry... } ] }

    Some sources send a single object directly. We normalise both shapes
    into a flat list of log record dicts.

    Special handling for Portal test format which wraps the body in a
    "Body" field with Event Hub metadata. Portal may send double-nested arrays.
    """
    try:
        data = json.loads(event_body)
    except json.JSONDecodeError:
        # Not JSON — treat the raw string as the message body
        return [{"message": event_body, "time": None}]

    # Unwrap double-nested arrays from Portal test (e.g., [[{...}]])
    while isinstance(data, list) and len(data) == 1 and isinstance(data[0], list):
        data = data[0]

    # Handle Portal test format: [{"Body": "...", "Properties": {...}}]
    if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
        if "Body" in data[0] and "Properties" in data[0]:
            # This is Portal test format - extract the actual body
            actual_body = data[0]["Body"]
            if isinstance(actual_body, str):
                return extract_records(actual_body)  # Recursively parse the actual body
            return extract_records(json.dumps(actual_body))

        # If it's a list of dicts (not Portal format), check if they're valid records
        # A valid record should have dict elements, not nested lists
        flat_records = []
        for item in data:
            if isinstance(item, dict):
                flat_records.append(item)
            elif isinstance(item, list):
                # Nested list - flatten it recursively
                flat_records.extend(extract_records(json.dumps(item)))
        if flat_records:
            return flat_records
        return data

    if isinstance(data, dict):
        if "records" in data:
            return data["records"]
        return [data]

    return [{"message": str(data), "time": None}]


# RFC 5424 MSGID: printable US-ASCII without spaces. Slashes are replaced too
# so operation names such as Microsoft.Compute/virtualMachines/write stay readable.
_MSG_ID_INVALID = re.compile(r"[^\x21-\x7e]|/")


def record_to_syslog(record: dict) -> bytes:
    """
    Convert a single Azure log record dict to a syslog-formatted byte string.

    Azure log records have variable schemas depending on the source service.
    Common timestamp fields are tried in priority order. The full record is
    serialised as JSON and placed in the syslog MSG field so Curator stores
    the complete, unmodified event for AI analysis.
    """
    timestamp = record_time(record)

    # Use the operationName or category as a MSG-ID hint in RFC 5424
    msg_id = (
        record.get("operationName")
        or record.get("category")
        or record.get("resourceType")
        or "-"
    )
    msg_id = _MSG_ID_INVALID.sub("_", str(msg_id))

    # Serialise the full record as the message body
    message = json.dumps(record, ensure_ascii=False, separators=(",", ":"))

    if SYSLOG_FORMAT == "rfc3164":
        return build_rfc3164(message, timestamp)
    else:
        return build_rfc5424(message, timestamp, msg_id)


# ---------------------------------------------------------------------------
# Azure Function entry point
# ---------------------------------------------------------------------------

@app.event_hub_message_trigger(
    arg_name="events",
    event_hub_name="%EVENT_HUB_NAME%",                  # set via App Setting EVENT_HUB_NAME
    connection="EventHubConnection",                     # App Setting name (identity-based: EventHubConnection__fullyQualifiedNamespace)
    cardinality="many",                                  # batch mode — process all available events
    consumer_group="%EVENT_HUB_CONSUMER_GROUP%",        # set via App Setting EVENT_HUB_CONSUMER_GROUP
)
# Without a retry policy the Event Hubs checkpoint advances even when the
# function raises, so a failed batch would be dropped. With this policy the
# host holds the checkpoint and retries (about 25 minutes in total) before
# giving up. Progress on the partition pauses while retrying.
@app.retry(
    strategy="exponential_backoff",
    max_retry_count="10",
    minimum_interval="00:00:05",
    maximum_interval="00:05:00",
)
def eventhub_to_curator(events: List[func.EventHubEvent]) -> None:
    """
    Main Function handler.
    Receives a batch of Event Hub events, extracts the Azure log records from
    each event's JSON envelope, and delivers the batch to Curator over a single
    TCP connection (syslog or forward protocol).

    Only delivery failures are raised (and so retried). Events that cannot be
    decoded are logged and skipped so one bad event does not block the batch.
    """
    if not CURATOR_HOST:
        logger.error(
            "CURATOR_HOST is not set. Configure it in Function App Application Settings."
        )
        return

    # Handle both single event (portal test) and list of events (production)
    if not isinstance(events, list):
        events = [events]

    all_records: List[Dict[str, Any]] = []

    for event in events:
        try:
            body = event.get_body().decode("utf-8")
            records = extract_records(body)
            for record in records:
                # Skip invalid records that aren't dicts. Log the type only,
                # never the content: records can hold personal data.
                if not isinstance(record, dict):
                    logger.warning("Skipping invalid record of type %s", type(record))
                    continue
                all_records.append(record)
        except Exception as exc:
            logger.error("Failed to process event: %s", exc, exc_info=True)
            # Continue processing remaining events — don't drop the whole batch

    if not all_records:
        logger.info("No records to send in this batch.")
        return

    # Route to the appropriate protocol handler
    try:
        if PROTOCOL == "forward":
            send_forward_to_curator(all_records)
        else:
            # Syslog protocol: convert each record to syslog format
            syslog_messages = [record_to_syslog(record) for record in all_records]
            logger.info(
                "Forwarding batch of %d syslog messages to Curator at %s:%d (%s, %s)",
                len(syslog_messages),
                CURATOR_HOST,
                CURATOR_PORT,
                CURATOR_PROTOCOL.upper(),
                SYSLOG_FORMAT.upper(),
            )
            send_to_curator(syslog_messages)
    except Exception as exc:
        # Raising here makes the Function host apply the retry policy above
        logger.error("Failed to deliver messages to Curator: %s", exc, exc_info=True)
        raise
