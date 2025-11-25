# Copyright 2018-2026 (c) KeySafe-Cloud, all rights reserved.
# SPDX-License-Identifier: MIT

"""
Common utility functions for command-line scripts.
"""

import logging
import sys


# setup logger
logger = logging.getLogger(__name__)


def ensure_file_extension(fname: str, fmt: str) -> str:
    """
    Ensure given filename ends with the specified format extension.

    :param fname: original filename (e.g., "report.txt", "data.json")
    :param fmt: target format extension (e.g., "csv", "json", "xlsx")
    :return: corrected filename (e.g., "report.csv")
    """
    # normalize the format extension requested
    target_ext = f".{fmt.lower()}"
    # check if fname already ends with the target extension
    if fname.strip().lower().endswith(target_ext):
        return fname
    # change/add extension of the fname
    parts = fname.rsplit(".", 1)
    base_name = parts[0]
    return f"{base_name}{target_ext}"


def unique_ordered_list(items: list[str]) -> list[str]:
    """
    Reduce items to a unique set, while maintaining order.

    :param items: list of string items
    :return: unique ordered list of items
    """
    if not items:
        return []
    seen = set()
    result = []
    for item in items:
        if item not in seen:
            result.append(item)
            seen.add(item)
    return result


def obfuscate(s: str, show: int = 6) -> str:
    """
    Obfuscate a string, showing only the last `show` characters.

    :param s: string to obfuscate
    :param show: number of characters to show at the end
    :return: obfuscated string
    """
    return f"OBFUSCATED:{s[-show:]}" if s else "OBFUSCATED:None"


def yn_choice(message: str, default: str = "y") -> bool:
    """
    Handle an interactive response to the given message/question.

    Based on https://stackoverflow.com/a/4741730/2315612
    combined with https://stackoverflow.com/a/54712937/2315612

    :param message: question to ask the user
    :param default: default answer for question, can be confirmed with enter
    :return: boolean True when question is confirmed via user input
    """
    choices = "Y/n" if default.lower() in ("y", "yes") else "y/N"
    try:
        choice = input(f"{message} ({choices}) ")
    except KeyboardInterrupt:
        logger.exception("Received keyboard interrupt, exit script.")
        sys.exit(1)
    except EOFError:
        logger.exception("Unexpected EOF, exit script.")
        sys.exit(1)
    values = ("y", "yes", "") if choices == "Y/n" else ("y", "yes")
    return choice.strip().lower() in values
