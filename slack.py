from datetime import datetime
import requests
from typing import Dict
import json
from urllib.parse import urlparse
from itertools import zip_longest

class SlackNotification():
    def _post_webhook(body, url):
        r = requests.post(url, json=body)
        if r.status_code != 200:
            return False

        return True

    def send_notification(url, diffs, target_url):
        domain = urlparse(target_url).netloc
        added = list(dict.fromkeys(diffs['added']))
        removed = list(dict.fromkeys(diffs['removed']))
        ok = True
        for a, r in zip_longest(added, removed):
            body = {
                "attachments": [
                    {
                        "color": "#03a1fc",
                        "blocks": [
                            {
                                "type": "header",
                                "text": {
                                    "type": "plain_text",
                                    "text": f"Differences detected in {domain}"
                                }
                            },
                            {
                                "type": "section",
                                "fields": [
                                    {
                                        "type": "mrkdwn",
                                        "text": f"*Added:*\n{a}"
                                    },
                                    {
                                        "type": "mrkdwn",
                                        "text": f"*Removed:*\n{r}"
                                    }
                                ]
                            },
                            {
                                "type": "section",
                                "fields": [
                                    {
                                        "type": "mrkdwn",
                                        "text": f"<{target_url}|View JSON Page>"
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }

            if not SlackNotification._post_webhook(body, url):
                ok = False
        
        return ok
