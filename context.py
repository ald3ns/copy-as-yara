from typing import Tuple, Optional
from binaryninja.function import Function
from binaryninjaui import UIContext, UIActionContext


class SelectionContext:
    """Class to handle selection context in Binary Ninja"""

    def __init__(self, context: UIActionContext):
        self.function = context.function
        if context.address is not None and isinstance(context.length, int):
            self.selection = (context.address, context.address + context.length)
        else:
            self.selection = None

    @classmethod
    def from_current_context(cls) -> "SelectionContext":
        """Get the current selection context from Binary Ninja UI"""
        ctx = UIContext.activeContext()
        handler = ctx.contentActionHandler()
        if handler:
            action_context = handler.actionContext()
            return cls(action_context)
        return None

    def is_valid(self) -> bool:
        """Check if the selection context is valid"""
        return self.function is not None and self.selection is not None
