class Bug:
    def __init__(self, func_name, bug_type, disass):
        self.function_name = func_name
        self.bug_type = bug_type
        self.code_context = disass
    
    def buffer_overflow(self):
        buffer_size = 0x0
        total_locals = 0x0
        print(f"[+] Buffer overflow via function {self.function_name} with buffer of size {buffer_size}, total local vars make {total_locals} bytes")
    
    