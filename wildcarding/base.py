from typing import Dict, Any
from ..instruction import InstructionInfo


class WildcardHandler:
    """Base class for architecture-specific wildcarding"""

    def __init__(self, bv):
        self.bv = bv
        self.arch = bv.arch

    def apply_wildcards(self, inst: InstructionInfo) -> None:
        """Apply wildcards to the instruction bytes"""
        raise NotImplementedError("Subclasses must implement this method")
