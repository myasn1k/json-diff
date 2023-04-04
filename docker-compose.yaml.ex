version: "3"

services:
  app:
    build: .
    network_mode: service:vpn
    depends_on:
      - vpn
    volumes:
      - ./db_vol:/db
      - ./src:/app
    environment:
      PYTHONUNBUFFERED: 1
      RW_DB_PATH: /db/
      SLACK: www.example.com
      MONITOR: www.example.com
      CHASH: XXXXX
      UHASH: XXXXX
      CTIS_URL: www.example.com
      CTIS_USER: user
      CTIS_PASS: pass
      ACTOR_NAME: actor
      OPERATION_NAME: operation
      OPERATION_DESCRIPTION: description

  vpn:
    image: ghcr.io/bubuntux/nordvpn
    cap_add:
      - NET_ADMIN
      - NET_RAW
    environment:
      - TOKEN=XXXX
      - CONNECT=Thailand
