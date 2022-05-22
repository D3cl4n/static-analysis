import function_data
from capstone import *
from elftools.elf.elffile import ELFFile

def populate_plt_map(data, addr):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for byte in md.disasm(data, addr):
        print(str(hex(byte.address)) + "\t" + byte.mnemonic + "\t" + byte.op_str)
            

def search(binary):
    print("[+] Analyzing binary: {}".format(binary))

    opcodes = b""
    addr = 0
    plt_map = {}
    plt_data = b""
    with open(binary, "rb") as f:
        elf = ELFFile(f)
        code = elf.get_section_by_name(".text")
        opcodes = code.data()
        addr = code["sh_addr"]
        plt_section = elf.get_section_by_name(".plt.sec")
        plt_data = plt_section.data()
        plt_map = populate_plt_map(plt_data, addr)

    func = function_data.Func([])
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for byte in md.disasm(opcodes, addr):
        func.instructions.append(byte)
    
    func.find_frame()
    func.print_instructions()
