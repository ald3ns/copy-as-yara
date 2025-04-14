from typing import List
from .base import BaseFormatter
from ..instruction import InstructionInfo


class CompactFormatter(BaseFormatter):
    """Format as compact hex string without comments"""

    def format(self, instructions: List[InstructionInfo], arch_name: str) -> str:
        if not instructions:
            return ""

        return " ".join([inst.formatted_hex() for inst in instructions])
