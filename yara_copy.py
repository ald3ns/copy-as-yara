import struct

opcodes = []
pneumonics = []

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
	#to_return += op + " " * (padding - len(op)) + " // " + pnu + "\n"
	to_return += f"{op}{' ' * (padding - len(op))} // {pnu} \n"

print(to_return)
