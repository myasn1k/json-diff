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
      RW_SLACK: www.example.com
      RW_MONITOR: www.example.com

  vpn:
    image: ghcr.io/bubuntux/nordvpn
    cap_add:
      - NET_ADMIN
      - NET_RAW
    environment:
      - USER=user@email.com
      - "PASS=pas$word"
      - CONNECT=Thailand
