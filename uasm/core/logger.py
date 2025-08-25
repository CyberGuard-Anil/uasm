"""
Logging System for UASM
Centralized logging configuration and utilities
"""

import logging
import logging.handlers
import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional


def setup_logger(name: str, config: Dict[str, Any], verbose: bool = False) -> logging.Logger:
    """Setup main logger with configuration"""
    
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, config.get('level', 'INFO').upper()))
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Create formatter
    formatter = logging.Formatter(
        config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    
    # Set console level based on verbose flag
    if verbose:
        console_handler.setLevel(logging.DEBUG)
    else:
        console_handler.setLevel(getattr(logging, config.get('level', 'INFO').upper()))
    
    logger.addHandler(console_handler)
    
    # File handler
    log_file = config.get('file', 'uasm.log')
    if log_file:
        # Ensure log directory exists
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Create rotating file handler
        max_bytes = _parse_size(config.get('max_file_size', '10MB'))
        backup_count = config.get('backup_count', 5)
        
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, 
            maxBytes=max_bytes,
            backupCount=backup_count
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.DEBUG)  # Always log debug to file
        
        logger.addHandler(file_handler)
    
    return logger


def create_module_logger(module_name: str) -> logging.Logger:
    """Create logger for a specific module"""
    logger_name = f"UASM.{module_name}"
    logger = logging.getLogger(logger_name)
    
    # If parent logger is not configured, create basic configuration
    if not logger.parent.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    
    return logger


def log_scan_start(logger: logging.Logger, target: str, modules: list):
    """Log scan start information"""
    logger.info("🚀 Starting UASM scan")
    logger.info(f"📍 Target: {target}")
    logger.info(f"🔧 Modules: {', '.join(modules)}")
    logger.info("=" * 60)


def log_scan_complete(logger: logging.Logger, duration: float, findings_count: int):
    """Log scan completion information"""
    logger.info("=" * 60)
    logger.info(f"✅ Scan completed in {duration:.2f} seconds")
    logger.info(f"📊 Total findings: {findings_count}")


def log_module_start(logger: logging.Logger, module_name: str, target: str):
    """Log module start"""
    logger.info(f"🔍 Starting {module_name} scan for {target}")


def log_module_complete(logger: logging.Logger, module_name: str, 
                       findings: int, duration: float):
    """Log module completion"""
    logger.info(f"✅ {module_name} completed: {findings} findings in {duration:.2f}s")


def log_vulnerability_found(logger: logging.Logger, title: str, 
                          severity: str, target: str):
    """Log vulnerability discovery"""
    severity_icons = {
        'critical': '🔴',
        'high': '🟠', 
        'medium': '🟡',
        'low': '🟢',
        'info': '🔵'
    }
    
    icon = severity_icons.get(severity.lower(), '⚪')
    logger.warning(f"{icon} {severity.upper()}: {title} on {target}")


def log_finding(logger: logging.Logger, category: str, title: str, target: str):
    """Log general finding"""
    logger.info(f"📋 [{category.upper()}] {title} - {target}")


def log_error_with_context(logger: logging.Logger, error: Exception, 
                          context: str, target: Optional[str] = None):
    """Log error with context information"""
    error_msg = f"❌ Error in {context}: {str(error)}"
    if target:
        error_msg += f" (Target: {target})"
    
    logger.error(error_msg)
    
    # Log stack trace in debug mode
    logger.debug(f"Stack trace for {context}:", exc_info=True)


def setup_module_logging(module_name: str, config: Dict[str, Any]) -> logging.Logger:
    """Setup logging for a specific module"""
    logger = create_module_logger(module_name)
    
    # Module-specific log file
    if config.get('module_logs', False):
        log_dir = Path(config.get('log_dir', 'logs'))
        log_dir.mkdir(parents=True, exist_ok=True)
        
        module_log_file = log_dir / f"{module_name.lower()}.log"
        
        file_handler = logging.FileHandler(module_log_file)
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.DEBUG)
        
        logger.addHandler(file_handler)
    
    return logger


def _parse_size(size_str: str) -> int:
    """Parse size string (e.g., '10MB') to bytes"""
    size_str = size_str.upper().strip()
    
    if size_str.endswith('KB'):
        return int(size_str[:-2]) * 1024
    elif size_str.endswith('MB'):
        return int(size_str[:-2]) * 1024 * 1024
    elif size_str.endswith('GB'):
        return int(size_str[:-2]) * 1024 * 1024 * 1024
    else:
        try:
            return int(size_str)
        except ValueError:
            return 10 * 1024 * 1024  # Default 10MB


class ScanProgressLogger:
    """Progress logger for scan operations"""
    
    def __init__(self, logger: logging.Logger, total_items: int, 
                 operation: str = "items"):
        self.logger = logger
        self.total_items = total_items
        self.operation = operation
        self.completed_items = 0
        self.last_percentage = 0
    
    def update(self, increment: int = 1):
        """Update progress"""
        self.completed_items += increment
        percentage = int((self.completed_items / self.total_items) * 100)
        
        # Log progress at 10% intervals
        if percentage >= self.last_percentage + 10:
            self.logger.info(
                f"📈 Progress: {percentage}% ({self.completed_items}/{self.total_items} {self.operation})"
            )
            self.last_percentage = percentage
    
    def complete(self):
        """Mark as complete"""
        self.logger.info(
            f"✅ Completed: {self.completed_items}/{self.total_items} {self.operation} processed"
        )


class PerformanceTimer:
    """Performance timing utility"""
    
    def __init__(self, logger: logging.Logger, operation: str):
        self.logger = logger
        self.operation = operation
        self.start_time = None
    
    def __enter__(self):
        import time
        self.start_time = time.time()
        self.logger.debug(f"⏱️  Starting: {self.operation}")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        import time
        duration = time.time() - self.start_time
        
        if exc_type is None:
            self.logger.debug(f"✅ Completed: {self.operation} in {duration:.2f}s")
        else:
            self.logger.error(f"❌ Failed: {self.operation} after {duration:.2f}s")


def configure_third_party_loggers():
    """Configure third-party library loggers"""
    # Reduce noise from requests library
    logging.getLogger('requests').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    
    # Reduce noise from matplotlib
    logging.getLogger('matplotlib').setLevel(logging.WARNING)
    
    # Reduce noise from sqlalchemy
    logging.getLogger('sqlalchemy').setLevel(logging.WARNING)


# Initialize third-party logger configuration
configure_third_party_loggers()

