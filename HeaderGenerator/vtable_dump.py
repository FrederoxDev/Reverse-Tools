import idaapi as api
import idautils as utils
import ida_name as idaname
import idc as idc
import json
import os
import subprocess
import sys
sys.path.append("../Reverse-Tools/CxxParser/")
import Lexer
import Parser
import Analyser
api.require("Analyser")
api.require("Lexer")
api.require("Parser")

amethyst_folder = os.environ.get("amethyst") + "/tools/"

asm_path = amethyst_folder + "vtable.asm"
cxx_path = amethyst_folder + "vtable.h"

names = dict(utils.Names())
selection = idc.read_selection_start()
idaname.NearestName(names)

address, n, pos = idaname.NearestName(names).find(selection)

class_name = api.demangle_name(n, 0)[12:]
print("Dumping vtable for: " + class_name)

if address > selection:
    start = list(names.keys())[pos - 1]
    finish = address
else:
    start = address
    finish = list(names.keys())[pos + 1]

linux_vtable_items = []

index = 0

while start < finish:
    func_ea = idc.get_qword(start)
    symbol_name = idc.get_func_name(func_ea)
    index += 1
    start += 8

    if symbol_name == "":
        continue
    
    demangled_name: str | None = api.demangle_name(symbol_name, 0)
    
    if demangled_name is None:
        print(f"IDA failed to demangle {symbol_name}")
        continue
    
    try:
        tokens = Lexer.Lexer(demangled_name).tokenise()
        function = Parser.Parser(tokens).parse()
        linux_vtable_items.append((symbol_name, demangled_name, function))
        
    except:
        print("ERROR WHILE PARSING LINUX DECLARATIONS")
        print(demangled_name)
        exit(1)
    
# Read symbols from windows BDS
symbol_dumper_path = "C:/Users/blake/Documents/Reverse-Tools/SymbolDumper/bin/Debug/net8.0/SymbolDumper.exe"
bds_pdb_path = "C:/Users/blake/Downloads/bedrock-server-1.20.51.01/bedrock_server.pdb"

result = subprocess.run(
    [symbol_dumper_path, bds_pdb_path, class_name], 
    capture_output=True, text=True, check=True
)

win_data_dump = json.loads(result.stdout)
win_class_items = []

for entry in win_data_dump:
    symbol_name = entry["symbol"]
    
    demangled_name: str | None = api.demangle_name(symbol_name, 0)
    
    if demangled_name is None:
        print(f"IDA failed to demangle {symbol_name}")
        continue
    
    try:
        tokens = Lexer.Lexer(demangled_name).tokenise()
        function = Parser.Parser(tokens).parse()
        win_class_items.append((symbol_name, demangled_name, function))
        
    except:
        print("ERROR WHILE PARSING WIN DECLARATIONS")
        print(demangled_name)
        exit(1)
        
for (linux_symbol, linux_demangled, linux_function) in linux_vtable_items:
    linux_name = Analyser.function_name(linux_function)
    
    name_matches = []
    
    for (win_symbol, win_demangled, win_function) in win_class_items:
        win_name = Analyser.function_name(win_function)
        
        if linux_name == win_name:
            name_matches.append(win_function)
            
    print(linux_name, len(name_matches))