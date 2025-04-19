import socket
import os
import re

import docker
from zeroconf import Zeroconf, ServiceInfo

DOMAIN_REGEX = os.environ.get("DOMAIN_REGEX", r".*\.local$")
PUBLISHED_IP_SETTING = os.environ.get("PUBLISHED_IP", "auto")

domain_pattern = re.compile(DOMAIN_REGEX)

# Docker client
client = docker.from_env()

# Track published services
zeroconf = Zeroconf()
label_cache = {}        # container_id → [hostnames]
published_services = {} # hostname → ServiceInfo

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


def is_valid_hostname(hostname):
    return domain_pattern.match(hostname) is not None

def parse_hostnames(label_value):
    return [h.strip() for h in re.split(r'[,\s]+', label_value) if h.strip()]

def publish_hostname(hostname, container_name=" unknown"):
    if not is_valid_hostname(hostname):
        print(f"[Skip] Not publishing non-.local hostname: {hostname}")
        return
    if hostname in published_services:
        return

    try:
        info = ServiceInfo(
            type_="_http._tcp.local.",
            name=f"{hostname}._http._tcp.local.",
            port=80,
            addresses=[socket.inet_aton(PUBLISHED_IP)],
            properties={},
            server=f"{hostname}."  # Hostname to publish
        )
        zeroconf.register_service(info)
        published_services[hostname] = info
        print(f"[Zeroconf:{container_name}] Published {hostname} → {PUBLISHED_IP}")
    except Exception as e:
        print(f"[Zeroconf:{container_name}] Failed to publish {hostname}: {e}")

def unpublish_hostname(hostname, container_name="unknown"):
    if not is_local_hostname(hostname):
        return
    info = published_services.pop(hostname, None)
    if info:
        try:
            zeroconf.unregister_service(info)
            print(f"[Zeroconf:{container_name}] Unpublished {hostname}")
        except Exception as e:
            print(f"[Zeroconf:{container_name}] Failed to unpublish {hostname}: {e}")

def get_caddy_labeled_containers():
    containers = client.containers.list(all=True)
    for container in containers:
        labels = container.attrs['Config'].get('Labels', {})
        if 'caddy' in labels:
            raw_label = labels['caddy']
            hostnames = parse_hostnames(raw_label)
            label_cache[container.id] = hostnames
            for hostname in hostnames:
                publish_hostname(hostname, container.name)
            print(f"[Startup] {container.name}: caddy={hostnames}")

def handle_event(event):
    if event['Type'] != 'container':
        return

    action = event['Action']
    container_id = event['id']

    if action in ['start', 'update']:
        try:
            container = client.containers.get(container_id)
            labels = container.attrs['Config'].get('Labels', {})
            if 'caddy' in labels:
                raw_label = labels['caddy']
                hostnames = parse_hostnames(raw_label)
                label_cache[container.id] = hostnames
                for hostname in hostnames:
                    publish_hostname(hostname, container.name)
                print(f"[Event: {action}] {container.name}: caddy={hostnames}")
        except docker.errors.NotFound:
            pass

    elif action in ['stop', 'die', 'destroy']:
        hostnames = label_cache.get(container_id, [])
        name = event.get('Actor', {}).get('Attributes', {}).get('name', container_id[:12])
        if hostnames:
            for hostname in hostnames:
                unpublish_hostname(hostname, name)
            print(f"[Event: {action}] {name} stopped or removed. Last known caddy={hostnames}")
        if action == 'destroy':
            label_cache.pop(container_id, None)

def main():
    print("Starting caddy label monitor...")
    print(f"[Config] DOMAIN_REGEX: {DOMAIN_REGEX}")
    print(f"[Config] PUBLISH_IP: {PUBLISHED_IP}")

    get_caddy_labeled_containers()

    try:
        for event in client.events(decode=True):
            handle_event(event)
    except KeyboardInterrupt:
        print("Stopping monitor...")
        for hostname in list(published_services.keys()):
            unpublish_hostname(hostname)
        zeroconf.close()

if __name__ == "__main__":
    main()