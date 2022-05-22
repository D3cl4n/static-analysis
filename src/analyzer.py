import function_data
import re
from capstone import *
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

def find_relocations(map, binary):
    with open(binary, "rb") as f:
        e = ELFFile(f)
        for section in e.iter_sections():
            if isinstance(section, RelocationSection):
                print(section.name)
                symbol_table = e.get_section(section["sh_link"])
                for relocation in section.iter_relocations():
                    symbol = symbol_table.get_symbol(relocation["r_info_sym"])
                    addr = hex(relocation["r_offset"])
                    print(symbol.name + "\t" + addr)
                    if map.get(addr) != None:
                        map[addr] = symbol.name
    return map

def populate_plt_map(data, addr, binary):
    ret_map = {}
    cnt = 0
    flag = 0
    symbol_offset = 0x0
    instr_offset = 0x0
    md = Cs(CS_ARCH_X86, CS_MODE_64)

    for byte in md.disasm(data, addr):
        print(str(hex(byte.address)) + "\t" + byte.mnemonic + "\t" + byte.op_str)
        
        if flag == 1:
            symbol_offset = int(symbol_offset, 16)
            symbol_addr = byte.address + symbol_offset
            ret_map.update({hex(symbol_addr) : 1})
            flag = 0
            symbol_offset = 0x0
            instr_offset = 0x0
        
        if "[rip +" in byte.op_str:
            flag = 1
            tmp = re.search("0x[a-f0-9]+", byte.op_str)
            symbol_offset = tmp.group(0)

        cnt += 1

    ret_map = find_relocations(ret_map, binary)
    return ret_map
            

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
        plt_map = populate_plt_map(plt_data, 0x1070, binary)
        print(plt_map)

    func = function_data.Func([])
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for byte in md.disasm(opcodes, addr):
        func.instructions.append(byte)
    
    func.find_frame()
    func.print_instructions()
