# JSON-diff

Save differences of an URL-fetched json file

## Features

- Differences are saved in the log file
- Old and new files are saved
- Slack integration
- NordVPN integration
- CTIS integration

## To run

1. Copy `docker-compose.yaml.ex` to `docker-compose.yaml` and edit it
	- Set `SLACK` for slack incoming webhook url
	- Set `MONITOR` as the url to be monitored
	- Set `TOKEN` for nordvpn authentication
	- Set `CONNECT` as the location of the nordvpn server
	- Set `CHASH` as the client hash (without the pid)
	- Set `UHASH` as th user hash (remember to escape dollar signs using dollar signs)
	- Set `CTIS_URL` as the CTIS url
	- Set `CTIS_USER` as the CTIS username
	- Set `CTIS_PASS` as the CTIS password
	- Set `ACTOR_NAME` as the CTIS intrusion-set entity to be used
	- Set `OPERATION_NAME` as the CTIS operation entity to be used
	- Set `OPERATION_DESCRIPTION` as the CTIS operation entity description to be used
2. Build docker compose: `docker-compose build app`
3. Append to your contab: `*/10 * * * * cd /PATH/TO/json-diff && ./run.sh MUTEX_NUMBER`

## Note

- To run multiple instances just copy the folder and repeat steps above
