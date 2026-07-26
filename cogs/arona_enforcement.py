from datetime import timedelta

import discord
from discord.ext import commands

from settings import SETTINGS


ARONA_MODERATION_REQUEST_FOOTER = "Arona -> Plana Moderation v1"
TIMEOUT_DURATION = timedelta(minutes=5)
VALID_REASONS = {
    "prompt_injection",
    "bullying",
    "both",
}


class AronaEnforcement(commands.Cog):
    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

    @staticmethod
    def _embed_fields(embed: discord.Embed) -> dict[str, str]:
        return {
            field.name: field.value
            for field in embed.fields
        }

    @staticmethod
    def _has_role(member: discord.Member, role_id: int) -> bool:
        return any(role.id == role_id for role in member.roles)

    async def _react(self, message: discord.Message, emoji: str) -> None:
        try:
            await message.add_reaction(emoji)
        except (discord.Forbidden, discord.HTTPException):
            pass

    @commands.Cog.listener()
    async def on_message(self, message: discord.Message) -> None:
        if (
            message.guild is None
            or message.channel.id != SETTINGS.arona_moderation_channel_id
            or message.author.id != SETTINGS.arona_bot_id
            or not isinstance(message.author, discord.Member)
            or not self._has_role(message.author, SETTINGS.md_bot_role_id)
        ):
            return

        request_embed = next(
            (
                embed
                for embed in message.embeds
                if embed.footer.text == ARONA_MODERATION_REQUEST_FOOTER
            ),
            None,
        )
        if request_embed is None:
            return

        fields = self._embed_fields(request_embed)
        reason = fields.get("reason")
        if reason not in VALID_REASONS:
            await self._react(message, "❌")
            return

        try:
            target_user_id = int(fields["target_user_id"])
            int(fields["source_channel_id"])
        except (KeyError, TypeError, ValueError):
            await self._react(message, "❌")
            return

        member = message.guild.get_member(target_user_id)
        if member is None:
            try:
                member = await message.guild.fetch_member(target_user_id)
            except (discord.Forbidden, discord.NotFound, discord.HTTPException):
                await self._react(message, "❌")
                return

        protected_role_ids = {
            SETTINGS.admin_role_id,
            SETTINGS.semiadmin_role_id,
        }
        if member.bot or any(
            role.id in protected_role_ids
            for role in member.roles
        ):
            await self._react(message, "🛡️")
            return

        timeout_until = discord.utils.utcnow() + TIMEOUT_DURATION
        current_timeout = member.timed_out_until
        if current_timeout is not None and current_timeout >= timeout_until:
            await self._react(message, "✅")
            return

        try:
            await member.timeout(
                timeout_until,
                reason=f"Arona LLM moderation: {reason}",
            )
        except (discord.Forbidden, discord.HTTPException) as exc:
            print(f"Arona moderation timeout failed for {target_user_id}: {exc}")
            await self._react(message, "❌")
            return

        await self._react(message, "✅")


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(AronaEnforcement(bot))
