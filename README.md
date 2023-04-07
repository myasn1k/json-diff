# JSON-diff

Save differences of an URL-fetched json file

## Features

- Differences are saved in the log file
- Old and new files are saved
- Slack integration
- NordVPN integration
- CTIS integration
- Telegram integration

## To run

1. Edit `docker-compose.yaml`
	- Set `TOKEN` for nordvpn authentication
	- Set `CONNECT` as the location of the nordvpn server
2. Copy `config_vol/config.sample.yaml` to `config_vol/config.yaml` and edit it
3. Build docker compose: `docker-compose build app`
4. Append to your contab: `*/10 * * * * cd /PATH/TO/json-diff && ./run.sh MUTEX_NUMBER`

## Note

- To run multiple instances just copy the folder and repeat steps above
