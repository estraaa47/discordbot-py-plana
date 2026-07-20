import discord
from discord.ext import commands

from settings import SETTINGS


ROLE_MESSAGE_TEXT = (
    "🇴 :OVERWATCH\n"
    "🇻 :VALORANT\n"
    "🇦 :APEX\n"
    "🇱 :League of Legends\n"
    "🇪 :Escape From Tarkov\n"
    "🅾️ :Other games"
)


class ReactionRole(commands.Cog):
    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    @commands.Cog.listener()
    async def on_ready(self) -> None:
        channel = self.bot.get_channel(SETTINGS.role_channel_id)
        if channel is None:
            print(f"역할 채널을 찾을 수 없습니다: {SETTINGS.role_channel_id}")
            return

        try:
            await channel.fetch_message(SETTINGS.role_message_id)
            return
        except discord.NotFound:
            pass
        except discord.HTTPException as exc:
            print(f"역할 메시지 확인 오류: {exc}")
            return

        message = await channel.send(ROLE_MESSAGE_TEXT)
        for emoji in SETTINGS.reaction_roles:
            await message.add_reaction(emoji)

        print(
            "새 역할 메시지를 생성했습니다. "
            f"settings.py의 role_message_id를 {message.id}로 갱신하세요."
        )

    @commands.Cog.listener()
    async def on_member_join(self, member) -> None:
        if member.bot:
            role = member.guild.get_role(SETTINGS.bot_role_id)
            if role is not None:
                await member.add_roles(role, reason="Bot 역할 지급")
            return

        channel = self.bot.get_channel(SETTINGS.welcome_channel_id)
        if channel is not None:
            await channel.send(
                f"{member.mention}さん 日本人ですか？初めまして！"
                "ruleチャンネルを読んでroleチャンネルで日本を選んでください！"
            )

    async def _update_role(self, payload, *, add: bool) -> None:
        if payload.message_id != SETTINGS.role_message_id:
            return

        role_id = SETTINGS.reaction_roles.get(payload.emoji.name)
        if role_id is None:
            return

        guild = self.bot.get_guild(payload.guild_id)
        if guild is None:
            return

        member = guild.get_member(payload.user_id)
        if member is None:
            try:
                member = await guild.fetch_member(payload.user_id)
            except discord.HTTPException:
                return

        if member.bot:
            return

        role = guild.get_role(role_id)
        if role is None:
            return

        if add:
            await member.add_roles(role)
        else:
            await member.remove_roles(role)

    @commands.Cog.listener()
    async def on_raw_reaction_add(self, payload) -> None:
        await self._update_role(payload, add=True)

    @commands.Cog.listener()
    async def on_raw_reaction_remove(self, payload) -> None:
        await self._update_role(payload, add=False)


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(ReactionRole(bot))
