import logging


class Logger:

    def __init__(self, name, default_level=logging.ERROR):
        self.logger = logging.getLogger(name)
        if not self.logger.handlers:
            format_str = "%(asctime)s:%(levelname)s (%(name)s) | PID:%(process)s | THREAD_ID:%(threadName)s|%(thread)d: - " \
                         "[%(module)s.%(funcName)s:%(lineno)d] --- %(message)s"

            formatter = logging.Formatter(fmt=format_str)
            handler = logging.StreamHandler()
            handler.setFormatter(formatter)
            self.logger.propagate = False
            self.logger.addHandler(handler)
            self.logger.setLevel(default_level)
            self.logger.DEBUG = logging.DEBUG
            self.logger.INFO = logging.INFO
            self.logger.WARNING = logging.WARNING
            self.logger.ERROR = logging.ERROR
            self.logger.CRITICAL = logging.CRITICAL

    @staticmethod
    def get_logger(logger_name):
        return Logger(logger_name).logger
