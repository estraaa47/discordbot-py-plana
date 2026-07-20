from pathlib import Path

import discord
from discord.ext import commands

from settings import SETTINGS


class PlanaBot(commands.Bot):
    def __init__(self) -> None:
        intents = discord.Intents.default()
        intents.members = True
        intents.message_content = True
        super().__init__(command_prefix=SETTINGS.command_prefix, intents=intents)

    async def setup_hook(self) -> None:
        cogs_path = Path(__file__).resolve().parent / "cogs"

        for cog_path in sorted(cogs_path.glob("*.py")):
            if cog_path.name.startswith("_"):
                continue

            extension = f"cogs.{cog_path.stem}"
            try:
                await self.load_extension(extension)
                print(f"[OK] Extension Loaded: {extension}")
            except Exception as exc:
                print(f"[ERROR] Failed to load extension {extension}: {exc}")

    async def on_ready(self) -> None:
        await self.change_presence(status=discord.Status.online, activity=None)
        print(f"[OK] 로그인 완료: {self.user} (ID: {self.user.id})")


def main() -> None:
    if not SETTINGS.token:
        raise RuntimeError("TOKEN 환경변수가 설정되지 않았습니다.")

    bot = PlanaBot()
    try:
        bot.run(SETTINGS.token)
    except discord.errors.LoginFailure:
        print("Discord TOKEN이 올바르지 않습니다.")


if __name__ == "__main__":
    main()
