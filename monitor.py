import asyncio
import os
import re
import signal
import socket
from contextlib import suppress
from urllib.parse import urlparse

import aiodocker
from zeroconf import ServiceInfo
from zeroconf.asyncio import AsyncZeroconf


PUBLISHED_IP_SETTING = os.environ.get("PUBLISHED_IP", "auto")
REGISTER_CONCURRENCY = int(os.environ.get("MDNS_REGISTER_CONCURRENCY", "32"))

containers_dict = {}
prog = re.compile(r"^caddy(|_\d+)$")


def detect_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = None
    finally:
        s.close()

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
PUBLISHED_IP_BYTES = socket.inet_aton(PUBLISHED_IP)


def parse_site_addresses(labels):
    site_addresses = []
    for k, v in (labels or {}).items():
        if prog.match(k):
            site_addresses.extend(re.split(r"[,\s]+", v.strip()))
    return [addr for addr in site_addresses if addr]


def build_service_info(site_address):
    raw = site_address.strip()

    # Accept all:
    #   x.local
    #   y.x.local
    #   http://x.local
    #   https://y.x.local.local:8443/path
    if "://" in raw:
        parsed = urlparse(raw)
        host = (parsed.hostname or "").rstrip(".").lower()
    else:
        host = raw.rstrip(".").lower()

    if not host.endswith(".local"):
        return None, None

    left = host[:-6]  # strip ".local"
    if not left:
        return None, None

    labels = [label for label in left.split(".") if label]
    if not labels:
        return None, None

    fqdn = ".".join(labels) + ".local"
    instance = labels[0]

    info = ServiceInfo(
        type_="_http._tcp.local.",
        name=f"{instance}._http._tcp.local.",
        port=80,
        addresses=[PUBLISHED_IP_BYTES],
        properties={},
        server=f"{fqdn}.",
    )
    return fqdn, info


async def register_info(aiozc, sem, name, fqdn, site_address, info):
    async with sem:
        try:
            task = await aiozc.async_register_service(info)
            await task
        except Exception as e:
            print(f"[{name}][REGISTER] Failed to register {fqdn} ({site_address}): {e!r}")
            return None
        else:
            print(f"[{name}][REGISTER] Success {fqdn} ('{site_address}') → {PUBLISHED_IP}")
            return info


async def unregister_info(aiozc, name, info):
    try:
        await aiozc.async_unregister_service(info)
        print(f"[{name}][UNREGISTER] Success {info.server}")
    except Exception as e:
        print(f"[{name}][UNREGISTER] Failed to unregister {info.server}: {e!r}")


async def handle_container_up_from_summary(aiozc, sem, summary):
    container_id = summary["Id"]
    name = (summary.get("Names") or [container_id[:12]])[0].lstrip("/")
    labels = summary.get("Labels") or {}

    site_addresses = parse_site_addresses(labels)
    if not site_addresses:
        return

    infos_to_register = []
    seen_servers = set()

    for site_address in site_addresses:
        fqdn, info = build_service_info(site_address)
        if info is None:
            print(f"[{name}][REGISTER] Skipping non-local or unsupported address '{site_address}'")
            continue

        if info.server in seen_servers:
            continue
        seen_servers.add(info.server)
        infos_to_register.append((fqdn, site_address, info))

    if not infos_to_register:
        return

    results = await asyncio.gather(
        *(
            register_info(aiozc, sem, name, fqdn, site_address, info)
            for fqdn, site_address, info in infos_to_register
        )
    )

    infos = [info for info in results if info is not None]
    if infos:
        containers_dict[container_id] = {"name": name, "infos": infos}


async def handle_container_down(aiozc, container_id):
    try:
        container_dict = containers_dict.pop(container_id)
    except KeyError:
        return

    name = container_dict["name"]
    infos = container_dict["infos"]

    await asyncio.gather(*(unregister_info(aiozc, name, info) for info in infos))


async def handle_event(aiozc, sem, event):
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
            await handle_container_down(aiozc, container_id)

        await handle_container_up_from_summary(aiozc, sem, summary)

    elif action in ["stop", "die", "destroy"]:
        await handle_container_down(aiozc, container_id)


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


async def event_loop(docker, aiozc, sem, stop_event):
    subscriber = docker.events.subscribe()
    try:
        while not stop_event.is_set():
            event = await subscriber.get()
            if event is None:
                break
            await handle_event(aiozc, sem, event)
    finally:
        with suppress(Exception):
            await docker.events.stop()


async def shutdown_all(aiozc):
    container_ids = list(containers_dict.keys())
    for container_id in container_ids:
        await handle_container_down(aiozc, container_id)


async def main():
    print("Starting...")
    print(f"[CONFIG] PUBLISHED_IP: {PUBLISHED_IP}")
    print(f"[CONFIG] MDNS_REGISTER_CONCURRENCY: {REGISTER_CONCURRENCY}")

    stop_event = asyncio.Event()
    sem = asyncio.Semaphore(REGISTER_CONCURRENCY)

    def request_shutdown(*_args):
        stop_event.set()

    signal.signal(signal.SIGTERM, request_shutdown)
    signal.signal(signal.SIGINT, request_shutdown)

    docker = aiodocker.Docker()
    aiozc = AsyncZeroconf()

    try:
        summaries = await list_startup_summaries(docker)
        await asyncio.gather(
            *(handle_container_up_from_summary(aiozc, sem, summary) for summary in summaries)
        )
        print("Startup complete.")

        event_task = asyncio.create_task(event_loop(docker, aiozc, sem, stop_event))
        await stop_event.wait()

        event_task.cancel()
        with suppress(asyncio.CancelledError):
            await event_task

    finally:
        print("Shutting down...")
        await shutdown_all(aiozc)
        await aiozc.async_close()
        await docker.close()
        print("Shutdown complete.")


if __name__ == "__main__":
    asyncio.run(main())