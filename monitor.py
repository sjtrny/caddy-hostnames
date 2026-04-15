import argparse
import os
import re
import signal
import socket

import docker
import tldextract
from zeroconf import Zeroconf, ServiceInfo


def exit_gracefully(*args):
    raise KeyboardInterrupt


signal.signal(signal.SIGTERM, exit_gracefully)

PUBLISHED_IP_SETTING = os.environ.get("PUBLISHED_IP", "auto")

client = docker.from_env()
zeroconf = Zeroconf()

containers_dict = {}


def detect_IP():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def get_published_ip():
    if PUBLISHED_IP_SETTING.lower() != "auto":
        return PUBLISHED_IP_SETTING
    return detect_IP()


PUBLISHED_IP = get_published_ip()


def handle_container_up_from_summary(summary):
    container_id = summary["Id"]
    name = (summary.get("Names") or [container_id[:12]])[0].lstrip("/")

    labels = summary.get("Labels") or {}
    
    caddy_label_value = None
    for k, v in labels.items():
        if prog.match(k):
            caddy_label_value = v
            break

    if caddy_label_value == None:
        return

    site_addresses = re.split(r"[,\s]+", caddy_label_value.strip())
    infos = []

    for site_address in filter(None, site_addresses):
        site_extract = tldextract.extract(site_address)

        if site_extract.domain != "local":
            print(f"[{name}][REGISTER] Skipping non-local address '{site_address}'")
            continue

        fqdn = f"{site_extract.subdomain}.{site_extract.domain}"

        info = ServiceInfo(
            type_="_http._tcp.local.",
            name=f"{site_extract.subdomain}._http._tcp.local.",
            port=80,
            addresses=[socket.inet_aton(PUBLISHED_IP)],
            properties={},
            server=f"{fqdn}.",
        )

        try:
            zeroconf.register_service(info)
        except Exception as e:
            print(f"[{name}][REGISTER] Failed to register {fqdn} ({site_address}): {repr(e)}")
        else:
            infos.append(info)
            print(f"[{name}][REGISTER] Success {fqdn} ('{site_address}') → {PUBLISHED_IP}")

    if infos:
        containers_dict[container_id] = {"name": name, "infos": infos}



def handle_container_down(container_id):
    try:
        container_dict = containers_dict.pop(container_id)
    except KeyError:
        return

    name = container_dict["name"]
    for info in container_dict["infos"]:
        try:
            zeroconf.unregister_service(info)
            print(f"[{name}][UNREGISTER] Success {info.server}")
        except Exception as e:
            print(f"[{name}][UNREGISTER] Failed to unregister {info.server}: {e!r}")


def handle_event(event):
    if event.get("Type") != "container":
        return

    action = event.get("Action")
    actor = event.get("Actor", {})
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
        # Optionally clear any previous registrations for this ID
        if container_id in containers_dict:
            handle_container_down(container_id)
        handle_container_up_from_summary(summary)
    elif action in ["stop", "die", "destroy"]:
        handle_container_down(container_id)


prog = re.compile("^caddy(|_\d+)$")


def main():
    print("Starting...")
    print(f"[CONFIG] PUBLISH_IP: {PUBLISHED_IP}")

    summaries = client.api.containers(all=True)

    for summary in summaries:
        handle_container_up_from_summary(summary)

    print("Startup complete.")

    try:
        for event in client.events(decode=True):
            handle_event(event)
    except KeyboardInterrupt:
        print("Shutting down...")

        container_ids = list(containers_dict.keys())
        for container_id in container_ids:
            handle_container_down(container_id)

        zeroconf.close()
        print("Shutdown complete.")


if __name__ == "__main__":
    main()
