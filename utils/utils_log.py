import logging

from configobj import ConfigObj

class utils_log():
    def __init__(self, name, log_level=None):
        level = log_level
        # logging.basicConfig(getattr('logging', level))
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level))
        self.logger.propagate = False
        ch = logging.StreamHandler()
        ch.setLevel(getattr(logging, level))
        formatter = logging.Formatter((
            '%(asctime)s [%(name)s] [%(funcName)s:%(lineno)s] [%(levelname)s] '
            '%(message)s'
        ))
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)
