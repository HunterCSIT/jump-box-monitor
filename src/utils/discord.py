

from utils.http import http_post

def create_discord_message(message: str, bot_token: str, channel_id: str):
    url = f"https://discordapp.com/api/channels/{channel_id}/messages"
    headers = {
        "Authorization": f"Bot {bot_token}",
        "User-Agent": "myBotThing (http://some.url, v0.1)",
        "Content-Type": "application/json"
    }
    payload = {"content": message}
    http_post(url, payload, headers=headers)
