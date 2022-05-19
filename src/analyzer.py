import binascii
from capstone import *

def search(binary):
    print("[+] Analyzing binary: {}".format(binary))

    opcodes = b""
    with open(binary, "rb") as f:
        chunk = f.read(16)
        while chunk:
            
            chunk = f.read(16)

    print(opcodes)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for byte in md.disasm(opcodes, 318):
        print("0x%x: \t%s\t%s" % (byte.address, byte.mnemonic, byte.op_str))
