from .default import DefaultFormatter
from .compact import CompactFormatter
from .rule import RuleFormatter


def get_formatter(format_type):
    """Factory function to get the appropriate formatter"""
    formatters = {
        "default": DefaultFormatter(),
        "compact": CompactFormatter(),
        "rule": RuleFormatter(),
    }

    return formatters.get(format_type, DefaultFormatter())
