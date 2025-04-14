from typing import List
from .base import BaseFormatter
from ..instruction import InstructionInfo


class DefaultFormatter(BaseFormatter):
    """Format as comment-annotated hex bytes"""

    def format(self, instructions: List[InstructionInfo], arch_name: str) -> str:
        if not instructions:
            return ""

        opcodes = [inst.formatted_hex() for inst in instructions]
        mnemonics = [inst.mnemonic for inst in instructions]

        # Determine padding for alignment
        padding = max([len(i) for i in opcodes]) + 1

        # Build the pretty yara text
        result = ""
        for op, mnemonic in zip(opcodes, mnemonics):
            result += f"{op}{' ' * (padding - len(op))} // {mnemonic} \n"

        return result
