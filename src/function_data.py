class Func:
    def __init__(self, instructions):
        self.instructions = []
        self.stack_frame = []

    def print_instructions(self):
        for line in self.stack_frame:
            print(line)

    def check_prologue(self, idx):
        is_prologue = [0, 0]
        if self.instructions[idx+1].mnemonic == "mov" and self.instructions[idx+1].op_str == "rbp, rsp":
            print(self.instructions[idx+2].mnemonic + "\t" + self.instructions[idx+2].op_str)
            is_prologue[0] = 1
        if self.instructions[idx+2].mnemonic == "sub" and "rsp, 0x" in self.instructions[idx+2].op_str:
            is_prologue[1] = 1
        
        if is_prologue[0] == 1 and is_prologue[1] == 1:
            for i in range(idx, len(self.instructions)):
                if self.instructions[i].mnemonic == "ret":
                    return 1, i
        
        return 0, 0

    def combine(self, element):
        return element.mnemonic + "\t" + element.op_str

    def find_frame(self):
        cnt = 0
        for x in range(0, len(self.instructions)):
            if self.instructions[x].mnemonic == "push" and self.instructions[x].op_str == "rbp":
                is_prologue, ret_idx = self.check_prologue(x)
                if is_prologue == 1:
                    for i in range(x, ret_idx):
                        self.stack_frame.append(self.combine(self.instructions[i]))
                    break
                else:
                    continue