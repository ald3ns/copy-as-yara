import struct

from binaryninja.log import log_error, log_debug, log_alert, log_warn
from binaryninja.binaryview import BinaryView
from binaryninja.enums import InstructionTextTokenType
from binaryninja.plugin import PluginCommand
from binaryninjaui import UIContext, UIActionContext
from PySide6.QtGui import QGuiApplication


# Stolen from 'snippets' plugin:
# https://github.com/Vector35/snippets/blob/680e7ef3b87a9aae289dab7673ab221d3e87bac6/__init__.py#L129
def setup_context() -> UIActionContext:
    """
    Get the current UIContext at the time of the plugin run.
    :return: UIActionContext object
    """
    ctx = UIContext.activeContext()
    handler = ctx.contentActionHandler()
    if handler:
        context = handler.actionContext()

    return context


# Stolen from 'snippets' plugin:
# https://github.com/Vector35/snippets/blob/680e7ef3b87a9aae289dab7673ab221d3e87bac6/__init__.py#97
def setup_globals(context) -> dict:
    """
    Get the global variables that are accessible in the python console (current_function, current_selection).
    :param context:
    :return:
    """
    snippet_globals = {}
    snippet_globals["current_function"] = None

    if context.function:
        snippet_globals["current_function"] = context.function

    # Get the current_selection
    if context.address is not None and isinstance(context.length, int):
        snippet_globals["current_selection"] = (
            context.address,
            context.address + context.length,
        )
    else:
        snippet_globals["current_selection"] = None

    return snippet_globals


def copy_as_yara(bv: BinaryView, wildcarding: bool = False) -> None:
    """

    :param bv: the binary view provided when plugin is called
    :param wildcarding: do the wildcard replacing for bytes?
    :return: None
    """
    opcodes = []
    mnemonics = []

    # Call this locally otherwise it will use the context from plugin load time
    context = setup_globals(setup_context())

    current_function = context["current_function"]
    current_selection = context["current_selection"]

    if current_function is None or current_selection is None:
        log_error("No function selected!")
    else:
        for block in current_function:
            dis_text = block.get_disassembly_text()

            for idx, inst in enumerate(dis_text):
                if (
                    inst.address >= current_selection[0]
                    and inst.address < current_selection[1]
                ):
                    # Get the size of instruction bytes to read based off of
                    # addr of next instruction in block.

                    # Probably a better way to do this but idk it lol
                    if (idx + 1) < len(dis_text):
                        machine_code = bv.read(
                            inst.address, (dis_text[idx + 1].address - inst.address)
                        ).hex()
                    else:
                        machine_code = bv.read(
                            inst.address, (block.end - dis_text[idx].address)
                        ).hex()

                    # Replace addresses with wildcards
                    if wildcarding:
                        for token in inst.tokens:
                            # Add in special case for calls to functions?
                            if str(token) == "call":
                                machine_code = machine_code[:2] + "?" * len(
                                    machine_code
                                )

                            # TODO: See if token confidence produces more accurate results
                            if (
                                token.type
                                == InstructionTextTokenType.PossibleAddressToken
                            ):
                                # Swap endianness
                                converted_addr = struct.pack(
                                    "<I", int(token.text, 16)
                                ).hex()
                                machine_code = machine_code.replace(
                                    converted_addr, "?" * len(converted_addr)
                                )

                    opcodes.append(
                        " ".join(
                            [
                                machine_code[i : i + 2]
                                for i in range(0, len(machine_code), 2)
                            ]
                        )
                    )
                    mnemonics.append(str(inst))

    # Build the pretty yara text
    padding = max([len(i) for i in opcodes]) + 1
    to_return = ""
    for op, pnu in zip(opcodes, mnemonics):
        to_return += f"{op}{' ' * (padding - len(op))} // {pnu} \n"

    # Copy to the clipboard
    clip = QGuiApplication.clipboard()
    clip.setText(f"{to_return}")


def run(bv: BinaryView) -> None:
    copy_as_yara(bv)


def run_wildcard(bv: BinaryView) -> None:
    copy_as_yara(bv, True)


PluginCommand.register("Copy for YARA\\Normal", "Copy the disassembly as is.", run)
PluginCommand.register(
    "Copy for YARA\\Address Wildcards",
    "Replace addresses with wildcards.",
    run_wildcard,
)
