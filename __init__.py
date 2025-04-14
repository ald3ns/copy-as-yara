from binaryninja.plugin import PluginCommand
from binaryninja.binaryview import BinaryView

from .context import SelectionContext
from .exporter import YaraExporter


# Plugin command handlers
def export_normal(bv: BinaryView) -> None:
    """Export selection as YARA pattern without wildcards"""
    exporter = YaraExporter(bv)
    exporter.export_to_clipboard(wildcarding=False)


def export_with_wildcards(bv: BinaryView) -> None:
    """Export selection as YARA pattern with address wildcards"""
    exporter = YaraExporter(bv)
    exporter.export_to_clipboard(wildcarding=True)


def export_as_rule(bv: BinaryView) -> None:
    """Export selection as complete YARA rule"""
    exporter = YaraExporter(bv)
    exporter.export_to_clipboard(wildcarding=True, format_type="rule")


def export_compact(bv: BinaryView) -> None:
    """Export selection as compact hex pattern"""
    exporter = YaraExporter(bv)
    exporter.export_to_clipboard(wildcarding=False, format_type="compact")


# Register plugin commands
def register_plugin():
    PluginCommand.register(
        "Copy for YARA\\Normal", "Copy the disassembly as is.", export_normal
    )

    PluginCommand.register(
        "Copy for YARA\\Address Wildcards",
        "Replace addresses with wildcards.",
        export_with_wildcards,
    )

    PluginCommand.register(
        "Copy for YARA\\Complete Rule", "Generate a complete YARA rule.", export_as_rule
    )

    PluginCommand.register(
        "Copy for YARA\\Compact Format", "Copy as compact hex pattern.", export_compact
    )


register_plugin()
