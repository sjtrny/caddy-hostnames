# caddy-hostnames

**Automatically publish `.local` hostnames from Docker containers via mDNS using [Caddy-Docker-Proxy](https://github.com/lucaslorentz/caddy-docker-proxy).**

This container monitors your Docker environment for containers that have a `caddy` label, and automatically advertises 
any `.local` hostnames in that label using mDNS.

This makes containers discoverable on your local network **without needing DNS or manual `/etc/hosts` edits**.

## Features

- Multiple hostnames per container
- Both space and comma separators
- Only .local domains are published (others are ignored)

## Configuration

Volumes:
- mount the docker socket to listen to docker events

Environment Variables
- `PUBLISHED_IP` (default `auto`), set the ip address to be be associated with the hostnames

## Example - Host mode

The simplest approach is to use `network_mode: host` so that the container can send/receive mDNS on the LAN.

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

  caddy-hostnames:
    image: ghcr.io/sjtrny/caddy-hostnames:release
    restart: unless-stopped
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - PUBLISHED_IP=auto

  hello:
    image: nginx
    restart: unless-stopped
    networks:
      - bridge
    labels:
      - caddy=hello.local
      - caddy.reverse_proxy={{upstreams 80}}
```

## Example - bridge or overlay networks

You can repeat mDNS traffic across LAN and bridge/overlay networks with an 
[mDNS Repeater](https://github.com/tommycusick/docker-mdns-repeater).

```
services:

  mdns-repeater:
    image: ghcr.io/tommycusick/mdns-repeater:latest
    restart: unless-stopped
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - EXTERNAL_INTERFACE=eno1         # Use your network interface name
      - DOCKER_NETWORK_NAME=bridge      # The docker network to repeat to
      - USE_MDNS_REPEATER=1             # Enable
      
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
  
  caddy-hostnames:
    image: ghcr.io/sjtrny/caddy-hostnames:release
    restart: unless-stopped
    networks:
      - bridge
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - PUBLISHED_IP=192.168.0.1

  hello:
    image: nginx
    restart: unless-stopped
    networks:
      - bridge
    labels:
      - caddy=hello.local
      - caddy.reverse_proxy={{upstreams 80}}

```