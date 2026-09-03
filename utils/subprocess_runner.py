"""
Safe Subprocess Runner
Executes Windows command-line and PowerShell tools with injection safeguards, timeouts, and error handling.
"""

import subprocess
import time
from dataclasses import dataclass
from typing import List, Optional
from utils.logger import get_logger

logger = get_logger()


@dataclass
class CommandResult:
    command: List[str]
    return_code: int
    stdout: str
    stderr: str
    success: bool
    duration_ms: float
    error_message: Optional[str] = None


def decode_output(raw_bytes: Optional[bytes]) -> str:
    """
    Safely decodes raw process byte output, falling back across Windows code pages.
    """
    if not raw_bytes:
        return ""
    
    # Try common encodings on Windows
    for encoding in ["utf-8", "cp1252", "cp437", "iso-8859-1"]:
        try:
            return raw_bytes.decode(encoding)
        except UnicodeDecodeError:
            continue
    # Lossy fallback if all strict decoders fail
    return raw_bytes.decode("utf-8", errors="replace")


def run_command(
    cmd_args: List[str],
    timeout_seconds: int = 30,
    cwd: Optional[str] = None
) -> CommandResult:
    """
    Safely executes a system command using subprocess.run with shell=False.

    :param cmd_args: List of command arguments (e.g. ["ping", "-n", "4", "8.8.8.8"])
    :param timeout_seconds: Maximum execution time before raising a timeout
    :param cwd: Optional working directory
    :return: CommandResult object
    """
    if not cmd_args or not isinstance(cmd_args, list):
        raise ValueError("cmd_args must be a non-empty list of string arguments.")

    # Convert all arguments to strings
    sanitized_args = [str(arg) for arg in cmd_args]
    cmd_str = " ".join(sanitized_args)
    logger.debug(f"Executing command: {cmd_str} (timeout={timeout_seconds}s)")

    start_time = time.perf_counter()
    try:
        process = subprocess.run(
            sanitized_args,
            shell=False,  # CRITICAL: Prevent command injection
            capture_output=True,
            timeout=timeout_seconds,
            cwd=cwd,
            creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
        )
        duration = (time.perf_counter() - start_time) * 1000.0

        stdout_clean = decode_output(process.stdout).strip()
        stderr_clean = decode_output(process.stderr).strip()
        is_success = (process.returncode == 0)

        if not is_success:
            logger.warning(f"Command '{sanitized_args[0]}' returned non-zero code {process.returncode}")

        return CommandResult(
            command=sanitized_args,
            return_code=process.returncode,
            stdout=stdout_clean,
            stderr=stderr_clean,
            success=is_success,
            duration_ms=round(duration, 2)
        )

    except subprocess.TimeoutExpired:
        duration = (time.perf_counter() - start_time) * 1000.0
        err_msg = f"Command timed out after {timeout_seconds} seconds."
        logger.error(f"Timeout on: {cmd_str}")
        return CommandResult(
            command=sanitized_args,
            return_code=-1,
            stdout="",
            stderr=err_msg,
            success=False,
            duration_ms=round(duration, 2),
            error_message=err_msg
        )
    except FileNotFoundError:
        duration = (time.perf_counter() - start_time) * 1000.0
        err_msg = f"Command executable not found: {sanitized_args[0]}"
        logger.error(err_msg)
        return CommandResult(
            command=sanitized_args,
            return_code=-1,
            stdout="",
            stderr=err_msg,
            success=False,
            duration_ms=round(duration, 2),
            error_message=err_msg
        )
    except Exception as e:
        duration = (time.perf_counter() - start_time) * 1000.0
        err_msg = f"Unexpected execution error: {str(e)}"
        logger.error(err_msg, exc_info=True)
        return CommandResult(
            command=sanitized_args,
            return_code=-1,
            stdout="",
            stderr=err_msg,
            success=False,
            duration_ms=round(duration, 2),
            error_message=err_msg
        )


def run_powershell(
    ps_command: str,
    timeout_seconds: int = 30
) -> CommandResult:
    """
    Safely executes a PowerShell command using -NoProfile -NonInteractive flags.
    """
    ps_args = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy", "Bypass",
        "-Command", ps_command
    ]
    return run_command(ps_args, timeout_seconds=timeout_seconds)
