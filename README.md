# caddy-hostnames

**Automatically publish `.local` hostnames from Docker containers via mDNS using [Caddy-Docker-Proxy](https://github.com/lucaslorentz/caddy-docker-proxy).**

This container monitors your Docker environment for containers that have a `caddy` label, and automatically advertises 
any `.local` hostnames in that label using mDNS.

This makes containers discoverable on your local network **without needing DNS or manual `/etc/hosts` edits**.

## Features

- Multiple hostnames per container
- Both space and comma separators
- Only .local domains are published (others are ignored)

## Docker Compose Example

Requirements:
- `network_mode: host` to receive mDNS traffic from LAN, or use an [mDNS Repeater](https://github.com/tommycusick/docker-mdns-repeater)
- mounting the docker socket to listen to docker events

```
services:

  caddy:
    image: lucaslorentz/caddy-docker-proxy:latest
    restart: unless-stopped
    networks:
      - bridge
    ports:
      - 80:80
      - 443:443
    environment:
      - CADDY_INGRESS_NETWORKS=bridge
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock

  hello:
    image: nginx
    restart: unless-stopped
    networks:
      - bridge
    labels:
      - caddy=hello.local
      - caddy.reverse_proxy={{upstreams 80}}
  
  caddy-hostnames:
    image: ghcr.io/sjtrny/caddy-hostnames:release
    restart: unless-stopped
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - DOMAIN_REGEX=.*\.local$         # Only .local names (default)
      - PUBLISHED_IP=auto      # Or use "auto" to auto-detect
```