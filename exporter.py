from binaryninja.binaryview import BinaryView
from binaryninja.log import log_error, log_debug
from PySide6.QtGui import QGuiApplication

from .context import SelectionContext
from .generator import YaraGenerator


class YaraExporter:
    """Main class to handle the export process"""

    def __init__(self, bv: BinaryView):
        self.bv = bv
        self.generator = YaraGenerator(bv)

    def export_to_clipboard(
        self, wildcarding: bool = False, format_type: str = "default"
    ) -> bool:
        """Process selection and export to clipboard"""
        # Get current context
        context = SelectionContext.from_current_context()

        if not context or not context.is_valid():
            log_error("No valid selection!")
            return False

        # Extract selected instructions
        if not self.generator.extract_instructions(context):
            log_error("Failed to extract instructions from selection")
            return False

        # Apply wildcards if requested
        self.generator.apply_wildcards(wildcarding)

        # Format as YARA
        yara_text = self.generator.format_as_yara(format_type)

        if not yara_text:
            log_error("Failed to generate YARA pattern")
            return False

        # Copy to clipboard
        clip = QGuiApplication.clipboard()
        clip.setText(yara_text)

        log_debug(
            f"Copied {len(self.generator.inst_list)} instructions as YARA pattern"
        )
        return True
