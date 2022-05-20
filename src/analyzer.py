from capstone import *
from elftools.elf.elffile import ELFFile

def search(binary):
    print("[+] Analyzing binary: {}".format(binary))

    opcodes = b""
    with open(binary, "rb") as f:
        elf = ELFFile(f)
        code = elf.get_section_by_name(".text")
        opcodes = code.data()

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for byte in md.disasm(opcodes, 0):
        print("0x%x: \t%s\t%s" % (byte.address, byte.mnemonic, byte.op_str))
