# utils/logger.py
"""
简单封装的 logger，项目各处可以 import 并使用：
from utils.logger import get_logger
logger = get_logger(__name__)
logger.info("...")
保持最低限度，默认打印到 stdout。
"""

import logging
import sys

def get_logger(name=__name__, level=logging.INFO):
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        fmt = "%(asctime)s %(levelname)s %(name)s: %(message)s"
        handler.setFormatter(logging.Formatter(fmt))
        logger.addHandler(handler)
    logger.setLevel(level)
    return logger
