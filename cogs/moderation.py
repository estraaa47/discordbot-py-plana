import random
from datetime import datetime, timedelta
from typing import Dict

import discord
from discord.ext import commands, tasks

from settings import SETTINGS


WARNING_MESSAGES = [
    "장문 도배는 멈춰주세요 長文の連投ですか？やめてください！",
    "장문 도배가 감지되었습니다 長文の連投が確認されました！",
    "장문은 금지입니다 長文は連投として判断します！やめてください！",
]

SPAM_MESSAGES = [
    "{mention}さん、連投は禁止です!",
    "{mention}さん、連投はやめてください！",
    "{mention}さん、連投はダメです！",
    "{mention}さん、チャットが早すぎます",
    "{mention}さん、連投なんて！管理者に全部言いつけます！",
]


class Moderation(commands.Cog):
    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot
        self.message_counts: Dict[int, int] = {}
        self.time_frames: Dict[int, datetime] = {}
        self.red_cards: Dict[int, int] = {}

    async def cog_load(self) -> None:
        self.decrease_red_cards.start()

    def cog_unload(self) -> None:
        self.decrease_red_cards.cancel()

    def _is_spamming(self, author_id: int) -> bool:
        now = datetime.now()
        time_frame = self.time_frames.get(author_id, now)
        message_count = self.message_counts.get(author_id, 0)

        self.time_frames[author_id] = now + timedelta(
            seconds=SETTINGS.spam_window_seconds
        )

        if now > time_frame:
            self.message_counts[author_id] = 0
            for user_id in list(self.time_frames):
                expiration = self.time_frames[user_id] + timedelta(
                    seconds=SETTINGS.state_expiration_seconds
                )
                if now > expiration:
                    self.time_frames.pop(user_id, None)
                    self.message_counts.pop(user_id, None)
            return False

        self.message_counts[author_id] = message_count + 1
        return message_count >= SETTINGS.spam_message_limit

    def _add_red_card(self, user_id: int) -> None:
        self.red_cards[user_id] = self.red_cards.get(user_id, 0) + 1

    async def _apply_restricted_role(self, message) -> None:
        if self.red_cards.get(message.author.id, 0) < 2 or message.guild is None:
            return

        role = message.guild.get_role(SETTINGS.restricted_role_id)
        if role is None:
            print(f"제한 역할을 찾을 수 없습니다: {SETTINGS.restricted_role_id}")
            return

        member = message.guild.get_member(message.author.id) or message.author
        await member.add_roles(role)

        admin_role = discord.utils.get(
            message.guild.roles, id=SETTINGS.admin_role_id
        )
        semiadmin_role = discord.utils.get(
            message.guild.roles, id=SETTINGS.semiadmin_role_id
        )
        manager_mentions = ",".join(
            role.mention for role in (admin_role, semiadmin_role) if role is not None
        )

        await message.channel.send(
            f"{message.author.mention}, {role.name} 역할을 부여했습니다 "
            f"役割を与えました！ {manager_mentions} 관리자가 올때까지 기다려주세요 "
            "管理者がくるまでお待ちください！"
        )

    @tasks.loop(minutes=1)
    async def decrease_red_cards(self) -> None:
        for user_id in list(self.red_cards):
            self.red_cards[user_id] -= 1
            if self.red_cards[user_id] <= 0:
                self.red_cards.pop(user_id, None)

    @decrease_red_cards.before_loop
    async def before_decrease_red_cards(self) -> None:
        await self.bot.wait_until_ready()

    @commands.Cog.listener()
    async def on_message(self, message) -> None:
        if message.author.bot:
            return

        if len(message.content) > SETTINGS.max_message_length:
            await message.channel.send(random.choice(WARNING_MESSAGES))
            self._add_red_card(message.author.id)
            await self._apply_restricted_role(message)
            return

        if self._is_spamming(message.author.id):
            spam_message = random.choice(SPAM_MESSAGES).format(
                mention=message.author.mention
            )
            await message.channel.send(spam_message)
            self.message_counts[message.author.id] = 0
            self._add_red_card(message.author.id)
            await self._apply_restricted_role(message)


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(Moderation(bot))
