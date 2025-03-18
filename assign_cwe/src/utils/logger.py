# src/utils/logger.py

import sys
from pathlib import Path
from loguru import logger
from datetime import datetime

def setup_logging(log_path: str = "./logs") -> None:
    """
    Set up application-wide logging configuration using Loguru.
    
    Args:
        log_path: Directory path for log files
    """
    # Create logs directory if it doesn't exist
    log_dir = Path(log_path)
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Remove default logger
    logger.remove()
    
    # Generate log filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"cwe_kb_{timestamp}.log"
    
    # Add console handler with color
    logger.add(
        sys.stdout,
        colorize=True,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
        level="INFO"
    )
    
    # Add file handler
    logger.add(
        str(log_file),
        rotation="100 MB",  # Rotate when file reaches 100MB
        retention="30 days",  # Keep logs for 30 days
        compression="zip",  # Compress rotated logs
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
        level="DEBUG",
        backtrace=True,  # Include backtrace for errors
        diagnose=True    # Include variable values in tracebacks
    )
    
    logger.info(f"Logging configured. Log file: {log_file}")

def get_logger(name: str = __name__):
    """
    Get a logger instance for the given name.
    
    Args:
        name: Logger name (typically __name__ of the module)
        
    Returns:
        Loguru logger instance
    """
    return logger.bind(name=name)