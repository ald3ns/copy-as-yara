from typing import List
from ..instruction import InstructionInfo


class BaseFormatter:
    """Base class for YARA formatters"""

    def format(self, instructions: List[InstructionInfo], arch_name: str) -> str:
        """Format instructions into YARA pattern"""
        raise NotImplementedError("Subclasses must implement this method")
