from typing import List
import idaapi
import idautils 
import ida_name
import idc
import sys
import json
import os
sys.path.append("../Reverse-Tools/Common/")
import Itanium
import Common
import x86_64
idaapi.require("Itanium")
idaapi.require("Common")
idaapi.require("x86_64")

tools_folder = os.path.join(os.environ.get("amethyst"), "tools")
targets = Common.load_json(os.path.join(tools_folder, "header_targets.json"))
linux_vtable_data = Common.load_json(os.path.join(tools_folder, "linux_vtable.json"))
win_server_data = Common.load_json(os.path.join(tools_folder, "server_symbols.json"))

names = dict(idautils.Names())
windows_vtables = []
loaded_data = {}

def try_get_symbol_direct(class_name, func_ea) -> str | None:
    symbols = win_server_data["address_to_symbols"][str(func_ea)]
    filtered_symbols = []
    
    for symbol in symbols:
        demangled_name: str | None = idaapi.demangle_name(symbol, 0)
        if not demangled_name:
            continue
        
        if "virtual " in demangled_name and f"@{class_name}@@" in symbol:
            filtered_symbols.append(symbol)
        
    if len(filtered_symbols) == 1:
        return filtered_symbols[0]
    
    print("\n--- Failed to match, remaining options: ---")
    for filtered in filtered_symbols:
        print(filtered)
    print("--- end --- \n")
    
    return None

# Vtable names need to be loaded externally, IDA can only read one symbol for an address.
# Read the data and reformat slightly to be easier to work with.
for vtable in win_server_data["vtables"]:
    windows_vtables.append((vtable["address"], vtable["symbol"], vtable["demangled"]))

print(f"Loaded {len(windows_vtables)} vtables")

# Read in any data needed and store the information needed for each file
for target in targets:
    file_path = target.get("filepath")
    classes = target.get("classes")
    
    loaded_data[file_path] = []
    
    for class_name in classes:
        windows_vtable_ea = x86_64.get_vtable_by_name(windows_vtables, class_name)
        windows_vtable_entries = x86_64.get_vtable_entries(names, windows_vtable_ea)
        
        windows_vtable = []
        for func_ea in windows_vtable_entries:
            symbol = try_get_symbol_direct(class_name, func_ea)
            print(symbol)
        
print(json.dumps(loaded_data))