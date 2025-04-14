from typing import List
from binaryninja.binaryview import BinaryView
from binaryninja.log import log_error, log_debug

from .context import SelectionContext
from .instruction import InstructionInfo
from .wildcarding import get_wildcard_handler
from .formatters import get_formatter


class YaraGenerator:
    """Class to handle YARA signature generation"""

    def __init__(self, bv: BinaryView):
        self.bv = bv
        self.arch = bv.arch
        self.arch_name = bv.arch.name
        self.inst_list = []
        self.wildcard_handler = get_wildcard_handler(bv)

    def extract_instructions(self, context: SelectionContext) -> bool:
        """Extract instructions from the selection"""
        if not context.is_valid():
            log_error("No valid selection!")
            return False

        self.inst_list = []

        # Extract all instructions in the selection
        for block in context.function:
            dis_text = block.get_disassembly_text()

            for idx, inst in enumerate(dis_text):
                if (
                    inst.address >= context.selection[0]
                    and inst.address < context.selection[1]
                ):

                    # Determine instruction size
                    if (idx + 1) < len(dis_text):
                        size = dis_text[idx + 1].address - inst.address
                    else:
                        size = block.end - inst.address

                    bytes_data = self.bv.read(inst.address, size)

                    inst_info = InstructionInfo(
                        address=inst.address,
                        bytes_data=bytes_data,
                        mnemonic=str(inst),
                        tokens=inst.tokens,
                    )

                    self.inst_list.append(inst_info)

        return len(self.inst_list) > 0

    def apply_wildcards(self, wildcarding: bool = False) -> None:
        """Apply wildcards to the instruction bytes based on architecture"""
        if not wildcarding:
            return

        for inst in self.inst_list:
            self.wildcard_handler.apply_wildcards(inst)

    def format_as_yara(self, format_type: str = "default") -> str:
        """Format instructions as YARA rule"""
        if not self.inst_list:
            return ""

        formatter = get_formatter(format_type)
        return formatter.format(self.inst_list, self.arch_name)
