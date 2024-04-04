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
#linux_vtable = Common.load_json(os.path.join(tools_folder, "linux_vtable.json"))
# server_symbols = Common.load_json(os.path.join(tools_folder, "server_symbols.json"))

names = dict(idautils.Names())
windows_vtables = x86_64.get_vtables()
print(f"Loaded {len(windows_vtables)} vtables")

loaded_data = {}

for target in targets:
    file_path = target.get("filepath")
    classes = target.get("classes")
    
    loaded_data[file_path] = []
    
    for class_name in classes:
        windows_vtable_ea = x86_64.get_vtable_by_name(windows_vtables, class_name)
        windows_vtable_entries = x86_64.get_vtable_entries(names, windows_vtable_ea)
        
        for ea in windows_vtable_entries:
            symbol_name = idc.get_func_name(ea)
            print(symbol_name)
        
        loaded_data[file_path].append({
            "class_name": class_name
        })
        
print(loaded_data)