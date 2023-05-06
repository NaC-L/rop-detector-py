import capstone

assembly_code = bytes.fromhex(
    'C1 C6 02 F9 55 48 F7 C3 D8 3B 6D 30 F5 31 34 24 5D 48 63 F6 4C 03 C6 E9 31 67 01 00 41 50 C3'
)

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

# Function to determine the size of the register
def register_size(reg):
    length = len(reg)
    if length == 2 and reg.endswith('l'):
        return 1
    elif length == 2 and  (reg.endswith('x') or reg.endswith('p') or reg.endswith('i') ):
        return 2
    elif reg.startswith('e') or reg.startswith('0x'):
        return 4
    elif reg.startswith('r'):
        return 8
    else:
        return 0

# disassemble the assembly code and track changes to RSP register

rsp_instructions = []
current_rsp = 0
for insn in md.disasm(assembly_code, 0):
    print(f"0x{insn.address:x}\t{insn.mnemonic}\t{insn.op_str}")

    if insn.mnemonic in {'push', 'pop'}:
        reg_size = register_size(insn.op_str)
        
        if insn.mnemonic == 'push':
            current_rsp -= reg_size
        else:
            current_rsp += reg_size
        rsp_instructions.append( [insn,current_rsp] )
    elif insn.mnemonic == 'pushfq':
        current_rsp -= 8
        rsp_instructions.append( [insn,current_rsp] )
    elif insn.mnemonic == 'popfq':
        current_rsp += 8
        rsp_instructions.append( [insn,current_rsp] )
    elif insn.mnemonic == 'add' and insn.op_str.startswith('rsp,'):
        current_rsp += int(insn.op_str[5:], 0)
        rsp_instructions.append( [insn,current_rsp] )
    elif insn.mnemonic == 'sub' and insn.op_str.startswith('rsp,'):
        current_rsp -= int(insn.op_str[5:], 0)
        rsp_instructions.append( [insn,current_rsp] )
    elif "[rsp" in insn.op_str or "[esp" in insn.op_str:
        print(insn.op_str)
        rsp_instructions.append( [insn,current_rsp] )
# compare the initial and final values of RSP


if current_rsp < 0:
    print("Return Address is being manipulated",hex(current_rsp))
elif current_rsp == 0:
    print("Everything is fine")
    exit(0)
elif current_rsp > 0:
    print("Return Address is manipulated",hex(current_rsp))



instructionlist = []
for i in rsp_instructions:
    if ( i[1] == current_rsp and current_rsp < 0 ) or f"sp + {hex(current_rsp)[2:]}" in i[0].op_str:
        instructionlist.append(i[0])

print(instructionlist[-1])