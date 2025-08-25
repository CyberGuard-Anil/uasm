"""
Universal Attack Surface Mapper (UASM)
A comprehensive cybersecurity tool for attack surface mapping and vulnerability assessment
"""

__version__ = "1.0.0"
__author__ = "UASM Development Team"
__license__ = "MIT"

from . import core
from . import modules
from . import utils

__all__ = ['core', 'modules', 'utils']

