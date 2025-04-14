from typing import List, Any


class InstructionInfo:
    """Class to represent a single instruction with metadata"""

    def __init__(
        self, address: int, bytes_data: bytes, mnemonic: str, tokens: List[Any]
    ):
        self.address = address
        self.bytes_data = bytes_data
        self.mnemonic = mnemonic
        self.tokens = tokens
        self.hex_str = bytes_data.hex()

    def formatted_hex(self) -> str:
        """Return space-separated hex bytes"""
        return " ".join(
            [self.hex_str[i : i + 2] for i in range(0, len(self.hex_str), 2)]
        )
