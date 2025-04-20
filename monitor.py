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


def handle_container_up(container_id):
    try:
        container = client.containers.get(container_id)
    except docker.errors.NotFound:
        return

    # If container has a caddy label
    labels = container.attrs["Config"].get("Labels", {})
    if "caddy" in labels:

        site_addresses = re.split(r"[,\s]+", labels["caddy"])

        for site_address in site_addresses:

            site_extract = tldextract.extract(site_address)

            if site_extract.domain != "local":
                print(
                    f"[{container.name}][REGISTER] Skipping non-local address '{site_address}'"
                )
                continue

            fqdn = site_extract.subdomain + "." + site_extract.domain

            info = ServiceInfo(
                type_="_http._tcp.local.",
                name=f"{site_extract.subdomain}._http._tcp.local.", # Use subdomain here for service name
                port=80,
                addresses=[socket.inet_aton(PUBLISHED_IP)],
                properties={},
                server=f"{fqdn}.", # Must append . to FQDN for mDNS hostname resolution
            )

            # Attempt to publish
            try:
                zeroconf.register_service(info)
            except Exception as e:
                print(
                    f"[{container.name}][REGISTER] Failed to register {fqdn} ({site_address}): {repr(e)}"
                )
            else:

                if container_id not in containers_dict:
                    containers_dict[container_id] = {
                        "container": container,
                        "infos": [],
                    }

                containers_dict[container_id]["infos"].append(info)

                print(
                    f"[{container.name}][REGISTER] Success {fqdn} ('{site_address}') → {PUBLISHED_IP}"
                )


def handle_container_down(container_id):
    try:
        container_dict = containers_dict.pop(container_id)
    except KeyError:
        pass
    else:
        container = container_dict["container"]
        for info in container_dict["infos"]:
            try:
                zeroconf.unregister_service(info)
                print(f"[{container.name}][UNREGISTER] Success {info.server}")
            except Exception as e:
                print(
                    f"[{container.name}][UNREGISTER] Failed to unregister {info.server}"
                )


def handle_event(event):
    if event["Type"] != "container":
        return

    action = event["Action"]
    container_id = event["id"]

    if action in ["start", "update"]:
        handle_container_up(container_id)
    elif action in ["stop", "die", "destroy"]:
        handle_container_down(container_id)


def main():
    print("Starting...")
    print(f"[CONFIG] PUBLISH_IP: {PUBLISHED_IP}")

    containers = client.containers.list(all=True)
    for container in containers:
        handle_container_up(container.id)

    print("Startup complete.")

    # Main event loop
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
