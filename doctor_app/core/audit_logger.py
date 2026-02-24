import logging
from pathlib import Path


LOGGER_NAME = "vaultq.doctor.audit"


def get_audit_logger() -> logging.Logger:
    logger = logging.getLogger(LOGGER_NAME)
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    logger.propagate = False

    # Resolve base directory
    base_dir = Path(__file__).resolve().parents[1]

    # Ensure logs directory exists
    log_dir = base_dir / "logs"
    log_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    logfile = log_dir / "doctor_app.log"

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = logging.FileHandler(logfile, encoding="utf-8")
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger
