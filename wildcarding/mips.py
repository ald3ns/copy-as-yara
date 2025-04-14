import struct
from binaryninja.enums import InstructionTextTokenType
from .base import WildcardHandler
from ..instruction import InstructionInfo


class MipsWildcardHandler(WildcardHandler):
    """Wildcard handler for MIPS architecture"""

    def apply_wildcards(self, inst: InstructionInfo) -> None:
        """Apply wildcards for MIPS architecture"""
        # MIPS-specific wildcarding logic
        for token in inst.tokens:
            # Handle jump/branch instructions
            if str(token) in ["j", "jal", "b", "beq", "bne"]:
                # Preserve opcode
                inst.hex_str = inst.hex_str[:2] + "?" * (len(inst.hex_str) - 2)
                return

            # Handle address references
            if token.type == InstructionTextTokenType.PossibleAddressToken:
                try:
                    converted_addr = struct.pack("<I", int(token.text, 16)).hex()
                    inst.hex_str = inst.hex_str.replace(
                        converted_addr, "?" * len(converted_addr)
                    )
                except (ValueError, struct.error):
                    pass  # Skip if conversion fails
