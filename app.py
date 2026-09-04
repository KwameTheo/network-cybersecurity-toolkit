"""
Network & Cybersecurity IT Support Toolkit
Main Application Entry Point
"""

import sys
import tkinter.messagebox as messagebox
from core.integrity_guard import assert_authenticity
from ui.app_window import AppWindow
from utils.logger import setup_logger

logger = setup_logger()


def main():
    """Initializes and runs the toolkit GUI with cryptographic provenance validation."""
    logger.info("Starting Network & Cybersecurity IT Support Toolkit (Author: Kwame_Theo)...")
    # Verify cryptographic provenance and anti-tamper integrity at startup
    if not assert_authenticity():
        logger.warning("Software provenance integrity check returned non-standard status.")

    try:
        app = AppWindow()
        app.mainloop()
        logger.info("Application closed normally.")
    except KeyboardInterrupt:
        logger.info("Application terminated by user.")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"Unhandled fatal exception: {e}", exc_info=True)
        try:
            messagebox.showerror(
                "Fatal Error",
                f"An unexpected error occurred:\n\n{str(e)}\n\nDetails have been recorded in logs/toolkit.log"
            )
        except Exception:
            pass
        sys.exit(1)


if __name__ == "__main__":
    main()
