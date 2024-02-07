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

# Process the symbols from the windows BDS
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
        
# Load optional parameter names
named_items = []

if os.path.exists(amethyst_folder + "param_names.json"):
    named_data = {}
    
    with open(amethyst_folder + "param_names.json", "r") as file:
        named_data = json.loads(file.read())    
        
    for demangled_name in named_data:
        tokens = Lexer.Lexer(demangled_name).tokenise()
        function = Parser.Parser(tokens).parse()
        named_items.append((function, named_data[demangled_name]))
        
    print(f"Loaded parameter names for {len(named_items)} functions")

matched_vtable = []
        
# Match functions between the windows BDS and linux BDS
for (linux_symbol, linux_demangled, linux_function) in linux_vtable_items:
    linux_name = Analyser.function_name(linux_function)
    linux_parameters = Analyser.simplify_parameters(Analyser.parameter_types(linux_function))
    
    print(f"{linux_name}({', '.join(linux_parameters)})")
    
    matches = []
    
    for (win_symbol, win_demangled, win_function) in win_class_items:
        win_name = Analyser.function_name(win_function)
        
        if linux_name == win_name:
            win_params = Analyser.simplify_parameters(Analyser.parameter_types(win_function))
            
            if linux_parameters == win_params:
                matches.append(win_function)
            
    if len(matches) != 1:
        print(f"[MATCH FAILED] {linux_name}({', '.join(linux_parameters)}) got {len(matches)} matches!")
        matched_vtable.append({
            "success": False,
            "symbol": linux_symbol
        })
        continue
    
    # Try and load parameter names
    param_name_match = []
    found_params = False
    
    for (named_function, param_names) in named_items:
        function_name = Analyser.function_name(named_function)
        
        if function_name == linux_name:
            function_params = Analyser.simplify_parameters(Analyser.parameter_types(named_function))
            
            if linux_parameters == function_params:
                param_name_match = param_names
                found_params = True
                break
    
    matched_vtable.append({
        "success": True,
        "symbol": win_symbol,
        "win_function": win_function,
        "param_names": param_name_match,
        "found_params": found_params
    })