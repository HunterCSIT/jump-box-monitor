
from logging import Logger
import traceback
from urllib.error import URLError

from utils.http import http_post_with_json


def create_discord_message(message: str, bot_token: str, channel_id: str, logger: Logger):
    url = f"https://discordapp.com/api/channels/{channel_id}/messages"
    headers = {
        "Authorization": f"Bot {bot_token}",
        "User-Agent": "myBotThing (http://some.url, v0.1)",
    }
    payload = {"content": message}
    try:
        http_post_with_json(url, payload, headers=headers)
    except URLError:
        logger.error("failed to send post request to " + url)
        logger.error(traceback.format_exc())
