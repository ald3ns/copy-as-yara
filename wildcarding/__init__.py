from .x86 import X86WildcardHandler
from .arm import ArmWildcardHandler
from .mips import MipsWildcardHandler


def get_wildcard_handler(bv):
    """Factory function to get the appropriate wildcard handler"""
    arch_name = bv.arch.name.lower()

    if "x86" in arch_name:
        return X86WildcardHandler(bv)
    elif "arm" in arch_name or "aarch64" in arch_name:
        return ArmWildcardHandler(bv)
    elif "mips" in arch_name:
        return MipsWildcardHandler(bv)
    else:
        # Default to x86 if unknown
        return X86WildcardHandler(bv)
