# JSON-diff

Save differences of an URL-fetched json file

## Features

- Differences are saved in the log file
- Old and new files are saved
- Slack integration

## To run

1. Install requirements 
2. Copy `docker-compose.yaml.ex` to `docker-compose.yaml` and edit it
	- Set `RW_SLACK` for slack incoming webhook url
	- Set `RW_MONITOR` as the url to be monitored
	- Set `USER` and `PASSWORD` for nordvpn authentication
	- Set `CONNECT` as the location of the nordvpn server
3. Build docker compose: `docker-compose build app`
4. Append to your contab: `*/10 * * * * cd /PATH/TO/json-diff && ./run.sh MUTEX_NUMBER`

## Note

- To run multiple instances just copy the folder and repeat steps above
