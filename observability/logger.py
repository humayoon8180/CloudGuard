"""
CloudGuard AI - Structured Observability Logger
-------------------------------------------------
Provides a pre-configured logger for the CloudGuard pipeline with
structured formatting suitable for both local development and production.

Usage:
    from observability.logger import get_logger
    logger = get_logger(__name__)
    logger.info("Pipeline started", extra={"incident_id": "INC-..."})
"""

import logging
import sys


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """
    Returns a named logger with consistent formatting.

    Args:
        name: Logger name (typically __name__ of the calling module).
        level: Logging level (default: INFO).

    Returns:
        Configured Logger instance.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        logger.addHandler(handler)
    logger.setLevel(level)
    return logger
