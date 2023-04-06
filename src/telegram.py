from datetime import datetime
import telebot
from urllib.parse import urlparse

class TelegramNotification():

    def send_notification(token, chat_id, diffs, target_url):
        domain = urlparse(target_url).netloc
        added = '\n'.join(diffs['added'])
        removed = '\n'.join(diffs['removed'])

        message = f"""\U0001F525\U0001F5A5 DDOSIA \U0001F525\U0001F5A5
Differences detected in {domain}
Added:\n{added}
Removed:\n{removed}
JSON page: {target_url}
        """
        return telebot.TeleBot(token).send_message(chat_id, message)
