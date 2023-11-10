"""
Operation types for the  replicated service in TOLERANCE
"""

from enum import IntEnum


class OperationType(IntEnum):
    """
    Enum representing the different types of operations for the replicated service in TOLERANCE
    """
    READ = 0
    WRITE = 1
