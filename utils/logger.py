import logging
import os
import sys

from utils.sentry import capture_error
from utils.sentry import capture_warning


class Logger:
    def __init__(self, logLevel):
        self.logger = logging.getLogger(__name__)
        self.setLevel(logLevel)

        # Add logging handler to print the log statement to standard output device
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.INFO)

        # https://stackoverflow.com/questions/533048/how-to-log-source-file-name-and-line-number-in-python
        # https://docs.python.org/3/library/logging.html#logrecord-attributes

        # Simplify log output for Production
        if os.getenv("CDX_APP_ENV") == "PRODUCTION":
            formatter = logging.Formatter(
                "%(levelname)-s - %(filename)s - Line:%(lineno)d - %(message)s - %(context)s", "%Y-%m-%d %H:%M:%S",
            )

        else:
            formatter = logging.Formatter(
                "[%(asctime)s.%(msecs)03d] %(levelname)-s - %(filename)s - {%(funcName)s:%(lineno)d} - %(message)s - %(context)s",
                "%Y-%m-%d %H:%M:%S",
            )

        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def setLevel(self, logLevel):
        self.logger.setLevel(logLevel)

    def debug(self, msg, *args, extra=None, **kwargs):
        """
        Log 'msg % args' with severity 'DEBUG'.

        To pass additional context, use keyword argument extra with
        a json value, e.g.

        """
        if extra is None:
            self.logger.debug(msg, *args, extra={"context": {}}, **kwargs)

        else:
            extra = {"context": extra}
            self.logger.debug(msg, *args, extra=extra, **kwargs)

    def info(self, msg, *args, extra=None, **kwargs):
        """
        Log 'msg % args' with severity 'INFO'.

        To pass additional context, use keyword argument extra with
        a json value, e.g.

        """
        if extra is None:
            self.logger.info(msg, *args, extra={"context": {}}, **kwargs)

        else:
            extra = {"context": extra}
            self.logger.info(msg, *args, extra=extra, **kwargs)

    def warning(self, msg, *args, extra=None, **kwargs):
        """
        Log 'msg % args' with severity 'WARNING'.

        To pass additional context, use keyword argument extra with
        a json value, e.g.

        """
        if os.getenv("CDX_APP_ENV") == "PRODUCTION":
            if extra:
                print(f"WARNING - {msg} - {extra}")

            else:
                print(f"WARNING - {msg}")

        else:
            if extra is None:
                self.logger.warning(msg, *args, extra={"context": {}}, **kwargs)

            else:
                extra = {"context": extra}
                self.logger.warning(msg, *args, extra=extra, **kwargs)

        error = sys.exc_info()
        if error:
            capture_error(msg, error, extra=extra)

        else:
            capture_warning(msg, extra=extra)

    def error(self, msg, *args, extra=None, **kwargs):
        """
        Log 'msg % args' with severity 'ERROR'.

        To pass additional context, use keyword argument extra with
        a json value, e.g.

        """
        if os.getenv("CDX_APP_ENV") == "PRODUCTION":
            if extra:
                print(f"ERROR - {msg} - {extra}")

            else:
                print(f"ERROR - {msg}")

        else:
            if extra is None:
                self.logger.error(msg, *args, extra={"context": {}}, **kwargs)

            else:
                extra = {"context": extra}
                self.logger.error(msg, *args, extra=extra, **kwargs)

        error = sys.exc_info()
        if error:
            capture_error(msg, error, extra=extra)

        else:
            capture_warning(msg, extra=extra)

    def exception(self, msg, *args, extra=None, **kwargs):
        """
        Log 'msg % args' with severity 'EXCEPTION'.

        To pass additional context, use keyword argument extra with
        a json value, e.g.

        """
        if os.getenv("CDX_APP_ENV") == "PRODUCTION":
            if extra:
                print(f"EXCEPTION - {msg} - {extra}")

            else:
                print(f"EXCEPTION - {msg}")

        else:
            if extra is None:
                self.logger.exception(msg, *args, extra={"context": {}}, **kwargs)

            else:
                extra = {"context": extra}
                self.logger.exception(msg, *args, extra=extra, **kwargs)

        error = sys.exc_info()
        if error:
            capture_error(msg, error, extra=extra)

        else:
            capture_warning(msg, extra=extra)

    def critical(self, msg, *args, extra=None, **kwargs):
        """
        Log 'msg % args' with severity 'CRITICAL'.

        To pass additional context, use keyword argument extra with
        a json value, e.g.

        """
        if os.getenv("CDX_APP_ENV") == "PRODUCTION":
            if extra:
                print(f"CRITICAL - {msg} - {extra}")

            else:
                print(f"CRITICAL - {msg}")

        else:
            if extra is None:
                self.logger.critical(msg, *args, extra={"context": {}}, **kwargs)

            else:
                extra = {"context": extra}
                self.logger.critical(msg, *args, extra=extra, **kwargs)

        error = sys.exc_info()
        if error:
            capture_error(msg, error, extra=extra)

        else:
            capture_warning(msg, extra=extra)


log_client = None


def get_logger(logLevel):
    global log_client

    """Call this method just once. To create a new logger."""
    log_client = Logger(logLevel) if not log_client else log_client

    return log_client
