import os
import logging
from dotenv import load_dotenv
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    filters,
    ContextTypes,
)
from virustotal_python import Virustotal
from pathlib import Path

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)

# Constants
MAX_FILE_SIZE = 500 * 1024 * 1024  # 500MB in bytes
SUPPORTED_EXTENSIONS = [".apk"]
TEMP_DIR = "temp_apks"
os.makedirs(TEMP_DIR, exist_ok=True)

# Initialize VirusTotal client
vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")
if not vt_api_key:
    raise ValueError("VIRUSTOTAL_API_KEY not found in environment variables")
vtotal = Virustotal(API_KEY=vt_api_key)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send a message when the command /start is issued."""
    user = update.effective_user
    await update.message.reply_text(
        f"Hi {user.mention_markdown_v2()}!\n\n"
        "I'm an APK Virus Scanner Bot\. Send me an APK file \(up to 500MB\) "
        "and I'll scan it for viruses using VirusTotal\.\n\n"
        "Note: For privacy reasons, I automatically delete your files after scanning\.",
        parse_mode="MarkdownV2"
    )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send a message when the command /help is issued."""
    help_text = (
        "📌 *How to use this bot:*\n\n"
        "1\. Send me an APK file \(up to 500MB\)\n"
        "2\. I'll upload it to VirusTotal for scanning\n"
        "3\. You'll receive a detailed report\n\n"
        "🔒 *Privacy Note:* All files are automatically deleted after scanning\."
    )
    await update.message.reply_text(help_text, parse_mode="MarkdownV2")

async def handle_apk(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle incoming APK files."""
    if not update.message.document and not update.message.document.mime_type == "application/vnd.android.package-archive":
        await update.message.reply_text("Please send an APK file (Android application package).")
        return

    document = update.message.document
    file_size = document.file_size

    if file_size > MAX_FILE_SIZE:
        await update.message.reply_text(
            f"File is too large. Maximum allowed size is 500MB. Your file: {file_size/1024/1024:.2f}MB"
        )
        return

    # Check file extension
    file_name = document.file_name or "unknown.apk"
    file_ext = Path(file_name).suffix.lower()
    if file_ext not in SUPPORTED_EXTENSIONS:
        await update.message.reply_text("Only APK files are supported.")
        return

    # Download the file
    await update.message.reply_text("📥 Downloading your APK file...")
    try:
        file = await context.bot.get_file(document.file_id)
        temp_path = os.path.join(TEMP_DIR, file_name)
        await file.download_to_drive(temp_path)
    except Exception as e:
        logger.error(f"Error downloading file: {e}")
        await update.message.reply_text("❌ Failed to download the file. Please try again.")
        return

    # Scan the file
    await update.message.reply_text("🔍 Scanning your APK for viruses...")
    try:
        # Upload to VirusTotal
        with open(temp_path, "rb") as f:
            upload_response = vtotal.request("files", files={"file": f}, method="POST")

        if upload_response.status_code != 200:
            raise Exception(f"VirusTotal upload failed: {upload_response.text}")

        # Get the analysis ID
        analysis_id = upload_response.data["id"]
        
        # Wait for analysis to complete (this can take some time)
        analysis_response = vtotal.request(f"analyses/{analysis_id}")
        while analysis_response.data["attributes"]["status"] != "completed":
            await context.bot.send_chat_action(
                chat_id=update.effective_chat.id, 
                action="typing"
            )
            analysis_response = vtotal.request(f"analyses/{analysis_id}")

        # Get the full report
        file_id = analysis_response.data["attributes"]["resource"]
        report_response = vtotal.request(f"files/{file_id}")

        # Parse the results
        stats = report_response.data["attributes"]["last_analysis_stats"]
        total_engines = stats["malicious"] + stats["suspicious"] + stats["undetected"] + stats["harmless"]
        malicious = stats["malicious"]
        suspicious = stats["suspicious"]
        harmless = stats["harmless"]

        # Prepare the report
        if malicious > 0:
            verdict = "❌ MALICIOUS"
            color = "🔴"
        elif suspicious > 0:
            verdict = "⚠️ SUSPICIOUS"
            color = "🟠"
        else:
            verdict = "✅ CLEAN"
            color = "🟢"

        report_text = (
            f"{color} *Scan Results for {file_name}:*\n\n"
            f"*Verdict:* {verdict}\n"
            f"*Malicious:* {malicious}/{total_engines}\n"
            f"*Suspicious:* {suspicious}/{total_engines}\n"
            f"*Harmless:* {harmless}/{total_engines}\n\n"
            "For detailed results, you can check the full report below:"
        )

        # Create a button to view the full report
        report_url = f"https://www.virustotal.com/gui/file/{file_id}/detection"
        keyboard = [
            [InlineKeyboardButton("View Full Report", url=report_url)],
            [InlineKeyboardButton("Delete File", callback_data=f"delete_{file_name}")]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)

        await update.message.reply_text(
            report_text,
            reply_markup=reply_markup,
            parse_mode="Markdown"
        )

    except Exception as e:
        logger.error(f"Error scanning file: {e}")
        await update.message.reply_text("❌ An error occurred while scanning the file. Please try again later.")
    finally:
        # Clean up
        try:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        except Exception as e:
            logger.error(f"Error deleting temp file: {e}")

async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle button callbacks."""
    query = update.callback_query
    await query.answer()

    if query.data.startswith("delete_"):
        file_name = query.data.split("_", 1)[1]
        temp_path = os.path.join(TEMP_DIR, file_name)
        
        if os.path.exists(temp_path):
            os.remove(temp_path)
            await query.edit_message_text(text=f"🗑️ File {file_name} has been deleted.")
        else:
            await query.edit_message_text(text="⚠️ File not found or already deleted.")

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Log errors and send a message to the user."""
    logger.error(msg="Exception while handling an update:", exc_info=context.error)
    
    if update.effective_message:
        await update.effective_message.reply_text(
            "❌ An unexpected error occurred. Please try again later."
        )

def main() -> None:
    """Start the bot."""
    # Create the Application
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    if not token:
        raise ValueError("TELEGRAM_BOT_TOKEN not found in environment variables")
    
    application = Application.builder().token(token).build()

    # Add handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(MessageHandler(filters.Document.APK, handle_apk))
    application.add_handler(CallbackQueryHandler(button_callback))
    
    # Add error handler
    application.add_error_handler(error_handler)

    # Run the bot
    application.run_polling()

if __name__ == "__main__":
    main()
