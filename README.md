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
	- Set `TOKEN` for nordvpn authentication
	- Set `CONNECT` as the location of the nordvpn server
	- Set `RW_CHASH` as the client hash (without the pid)
	- Set `RW_UHASH` as th user hash (remember to escape dollar signs using dollar signs)
3. Build docker compose: `docker-compose build app`
4. Append to your contab: `*/10 * * * * cd /PATH/TO/json-diff && ./run.sh MUTEX_NUMBER`

## Note

- To run multiple instances just copy the folder and repeat steps above
