import struct

from binaryninja import *

from binaryninja.log import log_error, log_debug, log_alert, log_warn
from binaryninja.plugin import BackgroundTaskThread, PluginCommand
from binaryninjaui import UIContext


# Stolen from 'snippets' plugin: https://github.com/Vector35/snippets/blob/680e7ef3b87a9aae289dab7673ab221d3e87bac6/__init__.py#L129
def setup_context():
    # Get UI context, try currently selected otherwise default to the first one if the snippet widget is selected.
    ctx = UIContext.activeContext()
    dummycontext = {
        "binaryView": None,
        "address": None,
        "function": None,
        "token": None,
        "lowLevelILFunction": None,
        "mediumLevelILFunction": None,
    }
    if not ctx:
        ctx = UIContext.allContexts()[0]

    else:
        handler = ctx.contentActionHandler()
        if handler:
            context = handler.actionContext()

    return context


# Stolen from 'snippets' plugin: https://github.com/Vector35/snippets/blob/680e7ef3b87a9aae289dab7673ab221d3e87bac6/__init__.py#97
def setupGlobals(context):
    snippetGlobals = {}
    snippetGlobals["current_view"] = context.binaryView
    snippetGlobals["bv"] = context.binaryView
    snippetGlobals["current_token"] = None
    snippetGlobals["current_hlil"] = None
    snippetGlobals["current_mlil"] = None
    snippetGlobals["current_function"] = None

    if context.function:
        snippetGlobals["current_function"] = context.function
        snippetGlobals["current_mlil"] = context.function.mlil
        snippetGlobals["current_hlil"] = context.function.hlil
        snippetGlobals["current_llil"] = context.function.llil
        if context.token:
            # Doubly nested because the first token is a HighlightTokenState
            snippetGlobals["current_token"] = context.token
        snippetGlobals["current_basic_block"] = context.function.get_basic_block_at(
            context.address
        )
    else:
        snippetGlobals["current_basic_block"] = None

    snippetGlobals["current_address"] = context.address
    snippetGlobals["here"] = context.address
    if context.address is not None and isinstance(context.length, int):
        snippetGlobals["current_selection"] = (
            context.address,
            context.address + context.length,
        )
    else:
        snippetGlobals["current_selection"] = None
    snippetGlobals["uicontext"] = context
    return snippetGlobals


def copy_as_yara(wildcarding: bool = False) -> None:
    opcodes = []
    pneumonics = []

    # Call this locally otherwise it will use the context from plugin load time
    context = setupGlobals(setup_context())

    current_function = context["current_function"]
    current_selection = context["current_selection"]
    bv = context["bv"]

    for block in current_function:
        dis_text = block.get_disassembly_text()

        for idx, inst in enumerate(dis_text):
            if (
                inst.address >= current_selection[0]
                and inst.address < current_selection[1]
            ):
                # Get the size of instruction bytes to read based off of addr of next instruction in block
                # Probably a better way to do this but idk it lol
                if (idx + 1) < len(dis_text):
                    machine_code = bv.read(
                        inst.address, (dis_text[idx + 1].address - inst.address)
                    ).hex()
                else:
                    machine_code = bv.read(
                        inst.address, (block.end - dis_text[idx].address)
                    ).hex()

                # If you don't want addresses in your rule, use this to replace them with wildcards
                for token in inst.tokens:
                    # Add in special case for calls to functions?
                    if str(token) == "call":
                        machine_code = machine_code[:2] + "?" * len(machine_code)

                    # TODO: See if token confidence produces more accurate results
                    if token.type == InstructionTextTokenType.PossibleAddressToken:
                        converted_addr = struct.pack("<I", int(token.text, 16)).hex()
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
                pneumonics.append(str(inst))

    # Print out pretty data :)
    padding = max([len(i) for i in opcodes]) + 1
    to_return = ""
    for op, pnu in zip(opcodes, pneumonics):
        # to_return += op + " " * (padding - len(op)) + " // " + pnu + "\n"
        to_return += f"{op}{' ' * (padding - len(op))} // {pnu} \n"

    print(to_return)


def run(bv):
    copy_as_yara()


PluginCommand.register("Copy As Yara", "Wildcarding", run)
