# JSON-diff

Save differences of an URL-fetched json file

## Features

- Differences are saved in the log file
- Old and new files are saved
- Slack integration
- NordVPN integration
- CTIS integration
- Telegram integration
- Airtable integration

## To run

1. Edit `docker-compose.yaml`
	- Set `TOKEN` for nordvpn authentication
	- Set `CONNECT` as the location of the nordvpn server
2. Copy `config_vol/config.sample.yaml` to `config_vol/config.yaml` and edit it
3. Build docker compose: `docker-compose build app`
4. Append to your contab: `*/10 * * * * cd /PATH/TO/json-diff && ./run.sh MUTEX_NUMBER`

## Note

- To run multiple instances just copy the folder and repeat steps above

# Slack to CTIS

Transfer slack notifications to Leonardo's CTIS platform.

## How to

Add to your crontab the following line: `*/5 * * * * /PATH/TO/run_bridge.sh >> /EVENTUAL/LOG/FILE 2>&1`

## Configuration

In json-diff's config file there is a section dedicated to slack to ctis integration; here's an example of it filled with information.

```
slack_to_ctis:
  slack_error_url: channel url for errors
  slack:
    token: xoxb-TOKEN
    channel_id: C03XXXXXXGN # channel un which the bridge will work
  ctis:
    url: https://cis.smth.com
    username: username
    password: password
    actor_name: actor
    operation_name: operation
    operation_description: description
  time_path: /PATH/TO/TIME/FILE # file in which the bridge will save the timestamp of the last message bridged
```
