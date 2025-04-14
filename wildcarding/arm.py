import struct
from binaryninja.enums import InstructionTextTokenType
from .base import WildcardHandler
from ..instruction import InstructionInfo


class ArmWildcardHandler(WildcardHandler):
    """Wildcard handler for ARM/AArch64 architecture"""

    def apply_wildcards(self, inst: InstructionInfo) -> None:
        """Apply wildcards for ARM/AArch64 architecture"""
        # ARM-specific wildcarding logic
        for token in inst.tokens:
            # Handle branch instructions
            if str(token) in ["b", "bl", "blx"]:
                # For ARM, preserve the first byte (condition codes)
                inst.hex_str = inst.hex_str[:2] + "?" * (len(inst.hex_str) - 2)
                return

            # Handle address references
            if token.type == InstructionTextTokenType.PossibleAddressToken:
                try:
                    # Handle different pointer sizes based on architecture
                    if "64" in self.arch.name:
                        fmt = "<Q"  # 64-bit little endian
                    else:
                        fmt = "<I"  # 32-bit little endian

                    addr_value = int(token.text, 16)
                    converted_addr = struct.pack(fmt, addr_value).hex()

                    # Replace the address with wildcards
                    inst.hex_str = inst.hex_str.replace(
                        converted_addr, "?" * len(converted_addr)
                    )
                except (ValueError, struct.error):
                    pass  # Skip if conversion fails
