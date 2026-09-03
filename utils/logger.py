"""
Application Logging System
Provides structured, non-sensitive audit logging to rotating files and console.
"""

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

# Base directory of the application
BASE_DIR = Path(__file__).resolve().parent.parent
LOGS_DIR = BASE_DIR / "logs"
LOG_FILE = LOGS_DIR / "toolkit.log"

# Global logger instance
_logger = None


def setup_logger(log_level: int = logging.INFO) -> logging.Logger:
    """
    Initializes and returns the central application logger.
    Logs are written to 'logs/toolkit.log' (max 2MB per file, 3 backups)
    and output to standard console stream.
    """
    global _logger
    if _logger is not None:
        return _logger

    # Ensure logs directory exists
    LOGS_DIR.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("NetSecToolkit")
    logger.setLevel(log_level)
    logger.propagate = False

    # Prevent duplicate handlers if re-initialized
    if not logger.handlers:
        # Formatter format: [Timestamp] [Level] [Module:Line] - Message
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] [%(name)s:%(funcName)s:%(lineno)d] - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )

        # Rotating file handler: up to 2MB per file, keeping 3 old logs
        file_handler = RotatingFileHandler(
            LOG_FILE,
            maxBytes=2 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8"
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

    _logger = logger
    _logger.info("Application logging system initialized.")
    return _logger


def get_logger() -> logging.Logger:
    """Returns the application logger instance, initializing if necessary."""
    global _logger
    if _logger is None:
        return setup_logger()
    return _logger
