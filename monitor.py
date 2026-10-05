import asyncio
import os
import re
import signal
import socket
import struct
import time
from collections import Counter
from contextlib import suppress
from urllib.parse import urlparse

import aiodocker


MDNS_GROUP = "224.0.0.251"
MDNS_PORT = 5353
MDNS_TTL = 120

TYPE_A = 1
TYPE_AAAA = 28
TYPE_NSEC = 47
TYPE_ANY = 255

CLASS_IN = 1
CLASS_ANY = 255
CLASS_CACHE_FLUSH = 0x8001
CLASS_MASK = 0x7FFF
UNICAST_RESPONSE = 0x8000
FLAG_RESPONSE_AUTHORITATIVE = 0x8400

PUBLISHED_IP_SETTING = os.environ.get("PUBLISHED_IP", "auto")

containers_dict = {}
prog = re.compile(r"^caddy(|_\d+)$")


def detect_ip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
    except Exception:
        ip = None
    finally:
        sock.close()

    if not ip or ip.startswith("127."):
        return None
    return ip


def get_published_ip():
    if PUBLISHED_IP_SETTING.lower() != "auto":
        return PUBLISHED_IP_SETTING

    ip = detect_ip()
    if ip is None:
        raise RuntimeError(
            "PUBLISHED_IP=auto could not determine a non-loopback IPv4 address; "
            "set PUBLISHED_IP explicitly."
        )
    return ip


PUBLISHED_IP = get_published_ip()


def parse_site_addresses(labels):
    site_addresses = []
    for key, value in (labels or {}).items():
        if prog.match(key):
            site_addresses.extend(re.split(r"[,\s]+", value.strip()))
    return [address for address in site_addresses if address]


def encode_name(name):
    encoded_labels = []
    total_length = 1
    for label in name.rstrip(".").split("."):
        encoded = label.encode("ascii")
        if not encoded or len(encoded) > 63:
            raise ValueError(f"invalid DNS label: {label!r}")
        encoded_labels.append(bytes([len(encoded)]) + encoded)
        total_length += len(encoded) + 1
    if total_length > 255:
        raise ValueError("DNS name exceeds 255 bytes")
    return b"".join(encoded_labels) + b"\0"


def parse_local_hostname(site_address):
    raw = site_address.strip()

    # Accept all:
    #   x.local
    #   y.x.local
    #   http://x.local
    #   https://y.x.local:8443/path
    if "://" in raw:
        parsed = urlparse(raw)
        host = (parsed.hostname or "").rstrip(".").lower()
    else:
        host = raw.rstrip(".").lower()

    if not host.endswith(".local"):
        return None

    left = host[:-6]
    if not left:
        return None

    labels = left.split(".")
    if any(not label for label in labels):
        return None

    hostname = ".".join(labels) + ".local"
    encode_name(hostname)
    return hostname


def read_name(data, position):
    labels = []
    end = None
    visited = set()

    while True:
        if position >= len(data) or position in visited:
            raise ValueError("invalid compressed DNS name")
        visited.add(position)

        length = data[position]
        position += 1
        if length == 0:
            break
        if length & 0xC0 == 0xC0:
            if position >= len(data):
                raise ValueError("truncated DNS pointer")
            if end is None:
                end = position + 1
            position = ((length & 0x3F) << 8) | data[position]
            continue
        if length & 0xC0 or length > 63 or position + length > len(data):
            raise ValueError("invalid DNS label")
        labels.append(data[position : position + length].decode("ascii"))
        position += length

    return ".".join(labels).lower() + ".", end if end is not None else position


def parse_questions(data):
    if len(data) < 12:
        raise ValueError("truncated DNS header")

    transaction_id, flags, question_count = struct.unpack_from("!HHH", data)
    if flags & 0x8000:
        return transaction_id, flags, []
    if question_count > 64:
        raise ValueError("too many DNS questions")

    position = 12
    questions = []
    for _ in range(question_count):
        name, position = read_name(data, position)
        if position + 4 > len(data):
            raise ValueError("truncated DNS question")
        record_type, record_class = struct.unpack_from("!HH", data, position)
        position += 4
        questions.append((name, record_type, record_class))

    return transaction_id, flags, questions


def record(name, record_type, rdata, ttl=MDNS_TTL):
    return (
        encode_name(name)
        + struct.pack("!HHIH", record_type, CLASS_CACHE_FLUSH, ttl, len(rdata))
        + rdata
    )


def a_record(name, published_ip, ttl=MDNS_TTL):
    return record(name, TYPE_A, socket.inet_aton(published_ip), ttl)


def nsec_record(name, ttl=MDNS_TTL):
    # Window 0, one bitmap byte, with only type A (bit 1) present. The NSEC
    # Next Domain Name is deliberately uncompressed as required by RFC 4034.
    rdata = encode_name(name) + b"\x00\x01\x40"
    return record(name, TYPE_NSEC, rdata, ttl)


def build_response(questions, hostnames, published_ip, transaction_id=0):
    answers = {}
    additionals = {}

    for name, record_type, record_class in questions:
        if name not in hostnames:
            continue
        if record_class & CLASS_MASK not in (CLASS_IN, CLASS_ANY):
            continue

        a_key = (name, TYPE_A)
        nsec_key = (name, TYPE_NSEC)
        if record_type in (TYPE_A, TYPE_ANY):
            answers[a_key] = a_record(name, published_ip)
            additionals[nsec_key] = nsec_record(name)
        elif record_type == TYPE_AAAA:
            answers[nsec_key] = nsec_record(name)

    if not answers:
        return None

    for key in answers:
        additionals.pop(key, None)

    return (
        struct.pack(
            "!6H",
            transaction_id,
            FLAG_RESPONSE_AUTHORITATIVE,
            0,
            len(answers),
            0,
            len(additionals),
        )
        + b"".join(answers.values())
        + b"".join(additionals.values())
    )


class HostnameResponder:
    """Answer bare mDNS hostname questions without DNS-SD advertisements."""

    def __init__(self, published_ip):
        self.published_ip = published_ip
        self._hostname_counts = Counter()
        self._hostnames = frozenset()
        self._recent_packets = {}
        self._socket = None
        self._loop = None

    @property
    def hostnames(self):
        return self._hostnames

    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        with suppress(AttributeError, OSError):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.bind(("", MDNS_PORT))

        membership = socket.inet_aton(MDNS_GROUP) + socket.inet_aton(self.published_ip)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership)
        with suppress(OSError):
            # Linux IP_MULTICAST_ALL: receive traffic only for memberships on
            # the selected interface, avoiding duplicate relayed queries.
            sock.setsockopt(socket.IPPROTO_IP, 49, 0)
        sock.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_MULTICAST_IF,
            socket.inet_aton(self.published_ip),
        )
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 255)
        sock.setblocking(False)

        self._socket = sock
        self._loop = asyncio.get_running_loop()
        self._loop.add_reader(sock.fileno(), self._read_ready)

    def add_hostname(self, hostname):
        canonical = hostname.rstrip(".").lower() + "."
        encode_name(canonical)
        self._hostname_counts[canonical] += 1
        self._hostnames = frozenset(self._hostname_counts)

    def remove_hostname(self, hostname):
        canonical = hostname.rstrip(".").lower() + "."
        if self._hostname_counts[canonical] <= 1:
            self._hostname_counts.pop(canonical, None)
            self._hostnames = frozenset(self._hostname_counts)
            self._send_goodbye(canonical)
        else:
            self._hostname_counts[canonical] -= 1

    def _send_goodbye(self, hostname):
        if self._socket is None:
            return
        payload = (
            struct.pack("!6H", 0, FLAG_RESPONSE_AUTHORITATIVE, 0, 1, 0, 0)
            + a_record(hostname, self.published_ip, ttl=0)
        )
        with suppress(OSError):
            self._socket.sendto(payload, (MDNS_GROUP, MDNS_PORT))

    def _is_duplicate(self, data, peer):
        now = time.monotonic()
        key = (peer, data)
        previous = self._recent_packets.get(key)
        self._recent_packets[key] = now

        if len(self._recent_packets) > 256:
            self._recent_packets = {
                packet: seen
                for packet, seen in self._recent_packets.items()
                if now - seen < 1.0
            }

        return previous is not None and now - previous < 0.05

    def _read_ready(self):
        while True:
            try:
                data, peer = self._socket.recvfrom(65535)
            except BlockingIOError:
                return
            except OSError as error:
                print(f"[MDNS] Receive failed: {error!r}")
                return

            if self._is_duplicate(data, peer):
                continue

            try:
                transaction_id, _, questions = parse_questions(data)
            except (UnicodeDecodeError, ValueError, struct.error):
                continue
            if not questions:
                continue

            legacy_unicast = peer[1] != MDNS_PORT
            if legacy_unicast:
                unicast_questions = questions
                multicast_questions = []
            else:
                unicast_questions = [
                    question
                    for question in questions
                    if question[2] & UNICAST_RESPONSE
                ]
                multicast_questions = [
                    question
                    for question in questions
                    if not question[2] & UNICAST_RESPONSE
                ]

            if multicast_questions:
                response = build_response(
                    multicast_questions,
                    self._hostnames,
                    self.published_ip,
                )
                if response is not None:
                    with suppress(OSError):
                        self._socket.sendto(response, (MDNS_GROUP, MDNS_PORT))

            if unicast_questions:
                response = build_response(
                    unicast_questions,
                    self._hostnames,
                    self.published_ip,
                    transaction_id if legacy_unicast else 0,
                )
                if response is not None:
                    with suppress(OSError):
                        self._socket.sendto(response, peer)

    def close(self):
        if self._socket is None:
            return
        self._loop.remove_reader(self._socket.fileno())
        self._socket.close()
        self._socket = None


async def handle_container_up_from_summary(responder, summary):
    container_id = summary["Id"]
    name = (summary.get("Names") or [container_id[:12]])[0].lstrip("/")
    labels = summary.get("Labels") or {}

    site_addresses = parse_site_addresses(labels)
    if not site_addresses:
        return

    hostnames = []
    seen_hostnames = set()

    for site_address in site_addresses:
        try:
            hostname = parse_local_hostname(site_address)
        except Exception as error:
            print(
                f"[{name}][REGISTER] Skipping invalid address "
                f"'{site_address}': {error!r}"
            )
            continue

        if hostname is None:
            print(
                f"[{name}][REGISTER] Skipping non-local or unsupported "
                f"address '{site_address}'"
            )
            continue
        if hostname in seen_hostnames:
            continue

        seen_hostnames.add(hostname)
        responder.add_hostname(hostname)
        hostnames.append(hostname)
        print(
            f"[{name}][REGISTER] Success {hostname} "
            f"('{site_address}') → {PUBLISHED_IP}"
        )

    if hostnames:
        containers_dict[container_id] = {"name": name, "hostnames": hostnames}


async def handle_container_down(responder, container_id):
    try:
        container = containers_dict.pop(container_id)
    except KeyError:
        return

    name = container["name"]
    for hostname in container["hostnames"]:
        responder.remove_hostname(hostname)
        print(f"[{name}][UNREGISTER] Success {hostname}.")


async def handle_event(responder, event):
    if event.get("Type") != "container":
        return

    action = event.get("Action")
    actor = event.get("Actor", {}) or {}
    attrs = actor.get("Attributes", {}) or {}
    container_id = actor.get("ID") or event.get("id")

    if not container_id:
        print(f"[WARN] Container event without ID: {event}")
        return

    if action in ["start", "update"]:
        summary = {
            "Id": container_id,
            "Names": [attrs.get("name", container_id[:12])],
            "Labels": attrs,
        }

        if container_id in containers_dict:
            await handle_container_down(responder, container_id)

        await handle_container_up_from_summary(responder, summary)

    elif action in ["stop", "die", "destroy"]:
        await handle_container_down(responder, container_id)


async def list_startup_summaries(docker):
    containers = await docker.containers.list()

    summaries = []
    for container in containers:
        data = await container.show()
        summaries.append(
            {
                "Id": data["Id"],
                "Names": [data.get("Name", data["Id"][:12]).lstrip("/")],
                "Labels": (data.get("Config") or {}).get("Labels") or {},
            }
        )
    return summaries


async def event_loop(docker, responder, stop_event):
    subscriber = docker.events.subscribe()
    try:
        while not stop_event.is_set():
            event = await subscriber.get()
            if event is None:
                break
            await handle_event(responder, event)
    finally:
        with suppress(Exception):
            await docker.events.stop()


async def shutdown_all(responder):
    for container_id in list(containers_dict):
        await handle_container_down(responder, container_id)


async def main():
    print("Starting...")
    print(f"[CONFIG] PUBLISHED_IP: {PUBLISHED_IP}")

    stop_event = asyncio.Event()

    def request_shutdown(*_args):
        stop_event.set()

    signal.signal(signal.SIGTERM, request_shutdown)
    signal.signal(signal.SIGINT, request_shutdown)

    docker = aiodocker.Docker()
    responder = HostnameResponder(PUBLISHED_IP)
    responder.start()

    try:
        summaries = await list_startup_summaries(docker)
        await asyncio.gather(
            *(handle_container_up_from_summary(responder, summary) for summary in summaries)
        )
        print(f"Startup complete. Publishing {len(responder.hostnames)} hostnames.")

        event_task = asyncio.create_task(event_loop(docker, responder, stop_event))
        await stop_event.wait()

        event_task.cancel()
        with suppress(asyncio.CancelledError):
            await event_task

    finally:
        print("Shutting down...")
        await shutdown_all(responder)
        responder.close()
        await docker.close()
        print("Shutdown complete.")


if __name__ == "__main__":
    asyncio.run(main())
