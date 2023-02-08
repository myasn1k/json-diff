from datetime import datetime
import requests
from typing import Dict
import json
from urllib.parse import urlparse

class SlackNotification():
    def _post_webhook(body, url):
        r = requests.post(url, json=body)
        if r.status_code != 200:
            return False

        return True

    def send_notification(url, diffs, target_url):
        domain = urlparse(target_url).netloc
        added = "\n".join(diffs['added'])
        removed = "\n".join(diffs['removed'])
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
                                    "text": f"*Added:*\n{added}"
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Removed:*\n{removed}"
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

        return SlackNotification._post_webhook(body, url)

