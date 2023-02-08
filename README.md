# JSON-diff

Save differences of an URL-fetched json file

## Features

- Differences are saved in the log file
- Old and new files are saved
- Slack integration

## To run

1. Install requirements 
2. Append to your contab: `*/10 * * * * cd /PATH/TO/json-diff && /usr/bin/python3 json-diff.py FULL_URL_TO_SCAN SLACK_MESSAGE_HOOK_URL`
