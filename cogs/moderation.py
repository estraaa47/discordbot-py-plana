import random
from datetime import datetime, timedelta
from typing import Dict

import discord
from discord.ext import commands, tasks

from settings import SETTINGS


DEFAULT_LOCALE = discord.Locale.korean

LONG_MESSAGE_WARNINGS = {
    discord.Locale.korean: [
        "{mention} 선생님, 메시지가 지나치게 깁니다. 내용을 나누어 전송해 주십시오.",
        "{mention} 선생님, 장문 메시지를 감지했습니다. 채팅 이용에 주의해 주십시오.",
        (
            "{mention} 선생님, 장문 전송은 자제해 주십시오. "
            "같은 행동이 반복되면 이용이 제한될 수 있습니다."
        ),
    ],
    discord.Locale.japanese: [
        "{mention}先生、メッセージが長すぎます。内容を分けて送信してください。",
        "{mention}先生、長文メッセージを検知しました。チャットの利用にはご注意ください。",
        (
            "{mention}先生、長文の送信はお控えください。"
            "同じ行為が続く場合、利用を制限する可能性があります。"
        ),
    ],
}

SPAM_WARNINGS = {
    discord.Locale.korean: [
        (
            "{mention} 선생님, 짧은 시간에 너무 많은 메시지가 전송되었습니다. "
            "잠시 기다려 주십시오."
        ),
        "{mention} 선생님, 연속 메시지를 감지했습니다. 채팅 속도를 낮춰 주십시오.",
        "{mention} 선생님, 도배는 허용되지 않습니다. 같은 행동을 반복하지 마십시오.",
    ],
    discord.Locale.japanese: [
        (
            "{mention}先生、短時間に多くのメッセージが送信されました。"
            "少しお待ちください。"
        ),
        "{mention}先生、連続したメッセージを検知しました。送信の間隔を空けてください。",
        "{mention}先生、連投は許可されていません。同じ行為を繰り返さないでください。",
    ],
}

RESTRICTED_ROLE_MESSAGES = {
    discord.Locale.korean: (
        "{mention} 선생님, 경고가 누적되어 {role} 역할을 부여했습니다."
        "{managers} 관리자가 확인할 때까지 기다려 주십시오."
    ),
    discord.Locale.japanese: (
        "{mention}先生、警告が累積したため、{role}ロールを付与しました。"
        "{managers} 管理者の確認が終わるまでお待ちください。"
    ),
}


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

    @staticmethod
    def _get_locale(message) -> discord.Locale:
        if (
            message.guild is not None
            and message.guild.preferred_locale == discord.Locale.japanese
        ):
            return discord.Locale.japanese

        return DEFAULT_LOCALE

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
        managers = f" {manager_mentions}" if manager_mentions else ""
        locale = self._get_locale(message)
        restricted_role_message = RESTRICTED_ROLE_MESSAGES[locale].format(
            mention=message.author.mention,
            role=role.mention,
            managers=managers,
        )
        await message.channel.send(restricted_role_message)

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
            locale = self._get_locale(message)
            warning_message = random.choice(LONG_MESSAGE_WARNINGS[locale]).format(
                mention=message.author.mention
            )
            await message.channel.send(warning_message)
            self._add_red_card(message.author.id)
            await self._apply_restricted_role(message)
            return

        if self._is_spamming(message.author.id):
            locale = self._get_locale(message)
            spam_message = random.choice(SPAM_WARNINGS[locale]).format(
                mention=message.author.mention
            )
            await message.channel.send(spam_message)
            self.message_counts[message.author.id] = 0
            self._add_red_card(message.author.id)
            await self._apply_restricted_role(message)


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(Moderation(bot))
