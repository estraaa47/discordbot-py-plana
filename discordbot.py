from cmath import log
from distutils.sysconfig import PREFIX
import discord
from discord import Embed
from dotenv import load_dotenv
import os
load_dotenv()
import requests
from discord.ext import commands
from datetime import datetime, timedelta
import threading
import random
import time
from bs4 import BeautifulSoup
import asyncio
import pytz
import openai

PREFIX = os.environ['PREFIX']
TOKEN = os.environ['TOKEN']
OPENAI_API_KEY = os.environ['GPT']
app = commands.Bot(command_prefix='/',intents=discord.Intents.all())
message_counts = {}
time_frames = {}
red_cards = {}

admin_id = 888839822184153089
semiadmin_id = 888817303188287519

openai.api_key = OPENAI_API_KEY

# 이전 대화 내용을 담을 리스트
conversation_history = []
last_conversation_reset_time = time.time()

# Time interval to keep data in memory (in seconds)
DATA_EXPIRATION_TIME = 3600

# 글자수 최대
threshold = 300

# 장문도배 경고문
WARNING_MESSAGES = ["장문 도배는 멈춰주세요 長文の連投ですか？やめてください！",
                   "장문 도배가 감지되었습니다 長文の連投が確認されました！",
                   "장문은 금지입니다 長文は連投として判断します！やめてください！"
                   ]

def get_osaka_weather():
    url = "https://weather.yahoo.co.jp/weather/jp/27/6200.html"
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    high_temp = soup.select_one('li.high em').text
    low_temp = soup.select_one('li.low em').text
    t1 = soup.select_one('tr.precip td:nth-child(2)').text
    t2 = soup.select_one('tr.precip td:nth-child(3)').text
    t3 = soup.select_one('tr.precip td:nth-child(4)').text
    t4 = soup.select_one('tr.precip td:nth-child(5)').text
    weather_icon = soup.select_one('p.pict img')
    weather_text = weather_icon['alt']
    img_tag = soup.select_one('p.pict img')
    image_url = img_tag['src']
    return high_temp, low_temp, t1, t2, t3, t4, weather_text, image_url
 

@app.event
async def on_ready():
    print('Done')
    await app.change_presence(status=discord.Status.online, activity=None)
    
    channel = app.get_channel(1032650685180813312)
    message_id = 1094422274607689759
    message = None
    async for msg in channel.history(limit=None):
        if msg.id == message_id:
            message = msg
            break
    if message is None:
        message = await channel.send("🇴 :OVERWATCH\n🇻 :VALORANT\n🇦 :APEX\n🇱 :League of Legends\n🇪 :Escape From Tarkov\n🅾️ :Other games")
        await message.add_reaction("🇴")
        await message.add_reaction("🇻")
        await message.add_reaction("🇦")
        await message.add_reaction("🇱")
        await message.add_reaction("🇪")
        await message.add_reaction("🅾️")

def is_spamming(author_id):
    now = datetime.now()
    time_frame = time_frames.get(author_id, now)
    message_count = message_counts.get(author_id, 0)
    
    # Set time frame for user to 2 seconds
    time_frames[author_id] = now + timedelta(seconds=2)
    
    # Reset message count and delete expired data if time frame has passed
    if now > time_frame:
        message_counts[author_id] = 0
        for key in list(time_frames.keys()):
            if now > time_frames[key] + timedelta(seconds=DATA_EXPIRATION_TIME):
                del time_frames[key]
                del message_counts[key]
                
        return False
    
    # Increase message count and check if spamming
    message_counts[author_id] = message_count + 1
    return message_count >= 5 # Change 5 to desired message count threshold

def decrease_red_cards():
    while True:
        for user_id in red_cards.copy():
            red_cards[user_id] -= 1
            if red_cards[user_id] == 0:
                del red_cards[user_id]
        time.sleep(60)

# 감소 쓰레드 시작
decrease_thread = threading.Thread(target=decrease_red_cards, daemon=True)
decrease_thread.start()

def add_red_card(user_id):
    red_cards[user_id] = red_cards.get(user_id, 0) + 1

@app.event
async def on_message(message):
    global last_conversation_reset_time
    spam_messages = [
    f"{message.author.mention} 도배는 금지되어 있습니다、連投は禁止です!",
    f"{message.author.mention} 도배는 그만해주세요、連投はやめてください！",
    f"{message.author.mention} 도배는 금지입니다、連投はダメです！",
    f"{message.author.mention} 채팅이 너무 빠릅니다、チャットが早すぎます",
    f"{message.author.mention} 도배는 관리자를 부르도록 하겠습니다、連投なんて！管理者に全部言いつけます！"
]
    message_length = len(message.content)

    if message.author == app.user:
        return

    if message.author.bot:
        return
    
    # 메세지 길이가 최대 글자수 돌파하는지 체크
    if message_length > threshold:
        # 경고발사
        WARNING_MESSAGE = random.choice(WARNING_MESSAGES)
        await message.channel.send(WARNING_MESSAGE)

        add_red_card(message.author.id)

        if red_cards.get(message.author.id, 0) >= 2:
            guild = message.guild
            role_id = 1087892271703261316 # Replace with the role ID you want to give to the user
            role = guild.get_role(role_id)
            adrole = discord.utils.get(message.guild.roles, id=admin_id)
            sadrole = discord.utils.get(message.guild.roles, id=semiadmin_id)
            member = guild.get_member(message.author.id)
            await member.add_roles(role)
            await message.channel.send(f"{message.author.mention}, {role.name} 역할을 부여했습니다 役割を与えました！ {adrole.mention},{sadrole.mention} 관리자가 올때까지 기다려주세요 管理者がくるまでお待ちください！")
            
    if message.author == app.user:
        return
    text = message.content
    if text.startswith('プラナ'):
        user_input = text[3:]
      
        current_time = time.time()
        time_elapsed = current_time - last_conversation_reset_time
        
        if time_elapsed >= 600:  # 10분(600초)이 경과하면 대화 초기화
            conversation_history.clear()
            last_conversation_reset_time = current_time
        # 이전 대화 내용을 포함하여 대화 진행
        conversation_history.append({"role": "user", "content": user_input})

        bot_response = openai.ChatCompletion.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "MD studioディスコードチャンネルサポートAIプラナです"},
                {"role": "user", "content": user_input}
            ] + conversation_history,  # 이전 대화 내용 추가
            temperature=0.5
        )

        # 대화 내용 업데이트
        conversation_history.append({"role": "assistant", "content": bot_response['choices'][0]['message']['content']})
        
        #print(bot_response)
        bot_text = '\n'.join([choice['message']['content'] for choice in bot_response['choices']])
        await message.channel.send(f"{bot_text}")

        return
    
    # Check if user is spamming
    elif is_spamming(message.author.id):
        spam_message = random.choice(spam_messages)
        await message.channel.send(spam_message)
        message_counts[message.author.id] = 0 # Reset message count for user

        add_red_card(message.author.id)

        if red_cards.get(message.author.id, 0) >= 2:
            guild = message.guild
            role_id = 1087892271703261316 # Replace with the role ID you want to give to the user
            role = guild.get_role(role_id)
            adrole = discord.utils.get(message.guild.roles, id=admin_id)
            sadrole = discord.utils.get(message.guild.roles, id=semiadmin_id)
            member = guild.get_member(message.author.id)
            await member.add_roles(role)
            await message.channel.send(f"{message.author.mention}, {role.name} 역할을 부여했습니다 役割を与えました！ {adrole.mention},{sadrole.mention} 관리자가 올때까지 기다려주세요 管理者がくるまでお待ちください！")
            

    return

@app.event
async def on_member_join(member):
    channel = app.get_channel(1087554522378948609)
    await channel.send(f'{member.mention}さん 日本人ですか？初めまして！ruleチャンネルを読んでroleチャンネルで日本を選んでください！') # channel에 보내기

ROLES = {
    "🇴": 1087692814462242816,  
    "🇻": 1087691245868032010,
    "🇦": 1087692165242683392,  
    "🇱": 1087693182441099275,
    "🇪": 1087693438423666809,  # 이모지와 해당 역할 ID를 수정해주세요.
    "🅾️": 1087693693122773054,
}

# 이벤트 핸들러
@app.event
async def on_raw_reaction_add(payload):
    if payload.message_id == 1094422274607689759:  # 역할 부여를 받을 메시지 ID를 수정해주세요.
        guild = app.get_guild(payload.guild_id)
        member = guild.get_member(payload.user_id)
        if member.bot:
            return

        emoji = payload.emoji.name
        if emoji in ROLES:
            role_id = ROLES[emoji]
            role = guild.get_role(role_id)
            await member.add_roles(role)

@app.event
async def on_raw_reaction_remove(payload):
    if payload.message_id == 1094422274607689759:  # 역할 부여를 받을 메시지 ID를 수정해주세요.
        guild = app.get_guild(payload.guild_id)
        member = guild.get_member(payload.user_id)
        if member.bot:
            return

        emoji = payload.emoji.name
        if emoji in ROLES:
            role_id = ROLES[emoji]
            role = guild.get_role(role_id)
            await member.remove_roles(role)

        
try:
    app.run(TOKEN)
except discord.errors.LoginFailure as e:
    print("Improper token has been passed.")
