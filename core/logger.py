"""
core/logger.py — Sistema de logging centralizado con soporte para consola y archivo.
"""

import logging
import sys
from pathlib import Path
from datetime import datetime

import config


def get_logger(name: str) -> logging.Logger:
    """
    Devuelve un logger configurado con handlers de consola y archivo.

    Args:
        name: Nombre del módulo (usualmente __name__).

    Returns:
        logging.Logger: Logger listo para usar.
    """
    logger = logging.getLogger(name)

    if logger.handlers:          # Evita duplicar handlers en reimportaciones
        return logger

    logger.setLevel(config.LOG_LEVEL)

    fmt = logging.Formatter(config.LOG_FORMAT, datefmt=config.LOG_DATE)

    # Handler: consola (stdout con colores ANSI)
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(_ColorFormatter(config.LOG_FORMAT, datefmt=config.LOG_DATE))
    logger.addHandler(ch)

    # Handler: archivo rotativo diario
    log_file = config.LOGS_DIR / f"scanner_{datetime.now():%Y%m%d}.log"
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    return logger


class _ColorFormatter(logging.Formatter):
    """Formatter con colores ANSI para la salida en consola."""

    _COLORS = {
        "DEBUG":    "\033[36m",   # Cyan
        "INFO":     "\033[32m",   # Green
        "WARNING":  "\033[33m",   # Yellow
        "ERROR":    "\033[31m",   # Red
        "CRITICAL": "\033[35m",   # Magenta
    }
    _RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self._COLORS.get(record.levelname, "")
        record.levelname = f"{color}{record.levelname:<8}{self._RESET}"
        return super().format(record)
