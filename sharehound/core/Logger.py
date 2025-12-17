#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Logger.py
# Author             : Remi Gascou (@podalirius_)
# Date created       : 12 Aug 2025

from __future__ import annotations

import os
import sys
import re
import time
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Optional

    from sharehound.core.Config import Config


class LogLevel(Enum):
    INFO = 1
    DEBUG = 2
    WARNING = 3
    ERROR = 4
    CRITICAL = 5


class Logger(object):
    """
    A Logger class that provides logging functionalities with various levels such as INFO, DEBUG, WARNING, ERROR, and CRITICAL.
    It supports color-coded output, which can be disabled, and can also log messages to a file.

    Attributes:
        __debug (bool): If True, debug level messages will be printed and logged.
        __nocolors (bool): If True, disables color-coded output.
        logfile (str|None): Path to a file where logs will be written. If None, logging to a file is disabled.

    Methods:
        __init__(debug=False, logfile=None, nocolors=False): Initializes the Logger instance.
        print(message=""): Prints a message to stdout and logs it to a file if logging is enabled.
        info(message): Logs a message at the INFO level.
        debug(message): Logs a message at the DEBUG level if debugging is enabled.
        error(message): Logs a message at the ERROR level.
    """

    config: Config
    logfile: Optional[str]

    def __init__(self, config: Config, logfile: Optional[str] = None):
        super(Logger, self).__init__()
        self.config = config
        self.logfile = logfile
        self.__indent_level = 0

        if sys.platform != "linux":
            self.config.no_colors = True

        if self.logfile is not None:
            if os.path.exists(self.logfile):
                k = 1
                while os.path.exists(self.logfile + (".%d" % k)):
                    k += 1
                self.logfile = self.logfile + (".%d" % k)
            open(self.logfile, "w").close()
            self.debug("Writting logs to logfile: '%s'" % self.logfile)

    def print(self, message: str = "", end: str = "\n"):
        """
        Prints a message to stdout and logs it to a file if logging is enabled.

        This method prints the provided message to the standard output and also logs it to a file if a log file path is specified during the Logger instance initialization. The message can include color codes for color-coded output, which can be disabled by setting the `nocolors` attribute to True.

        Args:
            message (str): The message to be printed and logged.
        """

        timestamp, indent = self._get_timestamp_and_indent()
        nocolor_message = re.sub(r"\x1b[\[]([0-9;]+)m", "", message)
        if self.config.no_colors:
            print("[%s] [-----] %s%s" % (timestamp, indent, nocolor_message), end=end)
        else:
            print("[%s] [-----] %s%s" % (timestamp, indent, message), end=end)
        self.write_to_logfile(
            "[%s] %s%s" % (timestamp, indent, nocolor_message), end=end
        )

    def increment_indent(self):
        """
        Increment the indentation level
        """
        self.__indent_level += 1

    def decrement_indent(self):
        """
        Decrement the indentation level
        """
        if self.__indent_level > 0:
            self.__indent_level -= 1

    def _get_timestamp_and_indent(self):
        """
        Get formatted timestamp and indentation string
        """
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        milliseconds = f".{int(time.time() * 1000) % 1000:03d}"
        timestamp_with_ms = timestamp + milliseconds
        indent = "  │ " * self.__indent_level
        return timestamp_with_ms, indent

    def info(self, message: str):
        """
        Logs a message at the INFO level.

        This method logs the provided message at the INFO level. The message can include color codes for color-coded output, which can be disabled by setting the `nocolors` attribute to True. The message is also logged to a file if a log file path is specified during the Logger instance initialization.

        Args:
            message (str): The message to be logged at the INFO level.
        """

        timestamp, indent = self._get_timestamp_and_indent()
        nocolor_message = re.sub(r"\x1b[\[]([0-9;]+)m", "", message)
        if self.config.no_colors:
            print("[%s] [info-] %s%s" % (timestamp, indent, nocolor_message))
        else:
            print("[%s] [\x1b[1;92minfo-\x1b[0m] %s%s" % (timestamp, indent, message))
        self.write_to_logfile("[%s] [info] %s%s" % (timestamp, indent, nocolor_message))

    def debug(self, message: str):
        """
        Logs a message at the DEBUG level if debugging is enabled.

        This method logs the provided message at the DEBUG level if the `debug` attribute is set to True during the Logger instance initialization. The message can include color codes for color-coded output, which can be disabled by setting the `nocolors` attribute to True.

        Args:
            message (str): The message to be logged.
        """

        if self.config.debug:
            timestamp, indent = self._get_timestamp_and_indent()
            nocolor_message = re.sub(r"\x1b[\[]([0-9;]+)m", "", message)
            if self.config.no_colors:
                print("[%s] [debug] %s%s" % (timestamp, indent, nocolor_message))
            else:
                print(
                    "[%s] [\x1b[1;93mdebug\x1b[0m] %s%s" % (timestamp, indent, message)
                )
            self.write_to_logfile(
                "[%s] [debug] %s%s" % (timestamp, indent, nocolor_message)
            )

    def error(self, message: str):
        """
        Logs an error message to the console and the log file.

        This method logs the provided error message to the standard error output and also logs it to a file if a log file path is specified during the Logger instance initialization. The message can include color codes for color-coded output, which can be disabled by setting the `nocolors` attribute to True.

        Args:
            message (str): The error message to be logged.
        """

        timestamp, indent = self._get_timestamp_and_indent()
        nocolor_message = re.sub(r"\x1b[\[]([0-9;]+)m", "", message)
        if self.config.no_colors:
            print("[%s] [error] %s%s" % (timestamp, indent, nocolor_message))
        else:
            print("[%s] [\x1b[1;91merror\x1b[0m] %s%s" % (timestamp, indent, message))
        self.write_to_logfile(
            "[%s] [error] %s%s" % (timestamp, indent, nocolor_message)
        )

    def write_to_logfile(self, message: str, end: str = "\n"):
        """
        Writes the provided message to the log file specified during Logger instance initialization.

        This method appends the provided message to the log file specified by the `logfile` attribute. If no log file path is specified, this method does nothing.

        Args:
            message (str): The message to be written to the log file.
        """

        if self.logfile is not None:
            f = open(self.logfile, "a")
            nocolor_message = re.sub(r"\x1b[\[]([0-9;]+)m", "", message)
            f.write(nocolor_message + end)
            f.close()


class TaskLogger:
    """
    A task-specific logger wrapper that provides isolated logging context for concurrent tasks.
    Each task gets its own TaskLogger instance to avoid indent level conflicts.
    """

    def __init__(self, base_logger: Logger, task_id: str = None):
        """
        Initialize a TaskLogger with a base logger and optional task identifier.

        Args:
            base_logger: The main Logger instance to wrap
            task_id: Optional identifier for this task (e.g., share name)
        """
        self.base_logger = base_logger
        self.task_id = task_id
        self.__indent_level = 0

    def _get_timestamp_and_indent(self):
        """
        Get formatted timestamp and indentation string for this task.
        """
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        milliseconds = f".{int(time.time() * 1000) % 1000:03d}"
        timestamp_with_ms = timestamp + milliseconds
        indent = "  │ " * self.__indent_level
        return timestamp_with_ms, indent

    def _format_message(self, message: str, level: str, color_code: str = None):
        """
        Format a log message with task-specific context.
        """
        timestamp, indent = self._get_timestamp_and_indent()
        nocolor_message = re.sub(r"\x1b[\[]([0-9;]+)m", "", message)

        # Add task identifier if available
        task_prefix = "[%s] " % self.task_id if self.task_id else ""

        if self.base_logger.config.no_colors:
            return f"[{timestamp}] [{level}] {task_prefix} {indent}{nocolor_message}"
        else:
            if color_code:
                return f"[{timestamp}] [{color_code}{level}\x1b[0m] {task_prefix} {indent}{message}"
            else:
                return f"[{timestamp}] [{level}] {task_prefix} {indent}{message}"

    def print(self, message: str = "", end: str = "\n"):
        """
        Print a message to stdout and log it to file.
        """
        formatted_message = self._format_message(message, "-----")
        print(formatted_message, end=end)
        self.base_logger.write_to_logfile(formatted_message, end=end)

    def increment_indent(self):
        """
        Increment the indentation level for this task.
        """
        self.__indent_level += 1

    def decrement_indent(self):
        """
        Decrement the indentation level for this task.
        """
        if self.__indent_level > 0:
            self.__indent_level -= 1

    def info(self, message: str):
        """
        Log a message at the INFO level.
        """
        formatted_message = self._format_message(message, "info-", "\x1b[1;92m")
        print(formatted_message)
        self.base_logger.write_to_logfile(formatted_message)

    def debug(self, message: str):
        """
        Log a message at the DEBUG level if debugging is enabled.
        """
        if self.base_logger.config.debug:
            formatted_message = self._format_message(message, "debug", "\x1b[1;93m")
            print(formatted_message)
            self.base_logger.write_to_logfile(formatted_message)

    def error(self, message: str):
        """
        Log an error message.
        """
        formatted_message = self._format_message(message, "error", "\x1b[1;91m")
        print(formatted_message)
        self.base_logger.write_to_logfile(formatted_message)

    def warning(self, message: str):
        """
        Log a warning message.
        """
        formatted_message = self._format_message(message, "warn-", "\x1b[1;95m")
        print(formatted_message)
        self.base_logger.write_to_logfile(formatted_message)

    def critical(self, message: str):
        """
        Log a critical message.
        """
        formatted_message = self._format_message(message, "crit-", "\x1b[1;91m")
        print(formatted_message)
        self.base_logger.write_to_logfile(formatted_message)
