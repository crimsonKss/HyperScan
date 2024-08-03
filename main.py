import asyncio
import logging.handlers
import math
import os
import re
from datetime import datetime

import discord
import requests.exceptions
from discord import app_commands
from dotenv import load_dotenv

load_dotenv()

token = str(os.getenv('BOT_TOKEN'))
vt_key = str(os.getenv('VT_KEY'))

logger = logging.getLogger('discord')
logger.setLevel(logging.DEBUG)
logging.getLogger('discord.http').setLevel(logging.INFO)

handler = logging.handlers.RotatingFileHandler(filename='discord.log', encoding='utf-8', maxBytes=32 * 1024 * 1024,
                                               # 32 MiB
                                               backupCount=5)
dt_fmt = '%Y-%m-%d %H:%M:%S'
formatter = logging.Formatter('[{asctime}] [{levelname:<8}] {name}: {message}', dt_fmt, style='{')
handler.setFormatter(formatter)
logger.addHandler(handler)


class Bot(discord.Client):
    def __init__(self) -> None:
        intents = discord.Intents.default()
        intents.message_content = True
        super().__init__(intents=intents)

        self.tree = app_commands.CommandTree(self)

    async def on_ready(self):
        print(f'\n-------------------'
              f'\n{self.user} is online.'
              f'\n-------------------')

    async def setup_hook(self) -> None:
        await self.tree.sync()


client = Bot()


@client.tree.context_menu(name='Get Raw Message Content')
@app_commands.allowed_installs(guilds=False, users=True)
@app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
async def testctx(interaction: discord.Interaction, message: discord.Message):  # noqa
    msg = message.content
    await interaction.response.send_message(f'`{msg}`', ephemeral=True)  # noqa


@client.tree.context_menu(name='Check URL Safety')
@app_commands.allowed_installs(guilds=False, users=True)
@app_commands.allowed_contexts(guilds=True, dms=True, private_channels=True)
async def scan(interaction: discord.Interaction, message: discord.Message):
    async def check_url(content):
        try:
            try:
                url_to_check = re.search(r'(?P<url>https?://\S[^/()]+)', content).group('url')
            except AttributeError:
                return '🚫 This message does not contain an URL.'
            api_url = (f'https://www.virustotal.com/vtapi/v2/url/report?apikey={vt_key}'
                       f'&resource={url_to_check}')

            response = requests.get(api_url)
            data = response.json()

            if data['verbose_msg'] == 'Resource does not exist in the dataset':
                return '⚠️ That is either not a valid URL or does not exist within the dataset'

            scan_date = datetime.strptime(data['scan_date'], '%Y-%m-%d %H:%M:%S')
            formatted_scan_date = f'<t:{math.floor(scan_date.timestamp())}:F>'

            results = f''
            if data['positives'] > 0:
                results = f'> ⚠️ **This website is suspicious. Use the link below for more info**'
            else:
                results = f'> ✅ This site is clean and safe to use!'

            class DataObj:
                def __init__(self):
                    self.url = f'> 🔗 Checked URL: `{url_to_check}`'
                    self.scan_date = f'> 📅 Scan Date: {formatted_scan_date}'
                    self.positives = f'> 🚩 Positives: `{data["positives"]}/{data["total"]}`'
                    self.results = results
                    self.full = f'> Click [here]({data["permalink"]}) to view the full results of this scan.'

            data_obj = DataObj()
            values = vars(data_obj).values()
            join = '\n> '.join(map(str, values))

            return (f"🌍 **Your Virus Scan Report:** \n\n{join}\n\n *Please note: The scan date is not the date you ran"
                    f" this command, it's the time the VirusTotal API most recently checked the website for viruses.*")

        except requests.exceptions.RequestException:
            return '⚠️ An error has occurred while checking this URL'

    reply = await check_url(content=message.content)

    embed = discord.Embed(colour=discord.Colour.blurple(), description=reply)
    await interaction.response.send_message(embed=embed, ephemeral=True)  # noqa


if __name__ == '__main__':
    try:
        asyncio.run(client.start(token))
    except KeyboardInterrupt:
        pass
