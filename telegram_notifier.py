import logging
import os

logger = logging.getLogger(__name__)

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

_telegram_enabled = False
_bot = None

try:
    if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
        import asyncio
        from telegram import Bot
        
        _bot = Bot(token=TELEGRAM_BOT_TOKEN)
        _telegram_enabled = True
        logger.info("Telegram notifications enabled")
    else:
        logger.info("Telegram not configured (set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)")
except ImportError:
    logger.warning("python-telegram-bot not installed, notifications disabled")
except Exception as e:
    logger.error(f"Telegram initialization failed: {e}")


def _send_message(message: str, critical: bool = False):
    """Send message via Telegram."""
    if not _telegram_enabled or not _bot:
        return
    
    try:
        import asyncio
        
        prefix = "🚨 CRITICAL" if critical else "ℹ️ INFO"
        
        async def send():
            await _bot.send_message(
                chat_id=TELEGRAM_CHAT_ID,
                text=f"{prefix}\n\n{message}",
                parse_mode="Markdown"
            )
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(send())
        loop.close()
        
    except Exception as e:
        logger.error(f"Failed to send Telegram notification: {e}")


def notify_new_ip(ip: str, endpoint: str):
    """Notify about new IP access."""
    message = f"New IP detected\nIP: `{ip}`\nEndpoint: `{endpoint}`"
    _send_message(message, critical=True)


def notify_shutdown():
    """Notify about shutdown initiation."""
    message = "Shutdown sequence initiated"
    _send_message(message, critical=True)


def notify_host_added(host: str, host_type: str):
    """Notify about host addition."""
    message = f"Host added\nType: {host_type}\nHost: `{host}`"
    _send_message(message, critical=False)


def notify_host_removed(host: str):
    """Notify about host removal."""
    message = f"Host removed\nHost: `{host}`"
    _send_message(message, critical=False)
