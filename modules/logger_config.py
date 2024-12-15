# -*- coding: utf-8 -*-

from sys import stdout
from logging import (
    getLogger,
    Formatter,
    StreamHandler,
    Logger as LoggerClass,
)
from logging.handlers import TimedRotatingFileHandler


def get_logger() -> LoggerClass:
    Logger = getLogger("crypt")
    if not Logger.hasHandlers():  # Add handlers only once
        FORMATTER = Formatter(
            "[{asctime}] - {name}({funcName}):{lineno}:{levelname} - {message}",
            "%Y-%m-%d %H:%M:%S",
            "{",
        )
        HANDLE_FILE = TimedRotatingFileHandler(
            "events.log", "D", 1, 5, "utf-8", False, False
        )
        HANDLE_FILE.setFormatter(FORMATTER)
        HANDLE_CONS = StreamHandler(stdout)
        HANDLE_CONS.setFormatter(FORMATTER)
        Logger.addHandler(HANDLE_CONS)
        Logger.addHandler(HANDLE_FILE)
    Logger.setLevel(1)
    return Logger
