from typing import List
import idaapi
import idautils 
import ida_name
import idc
import sys
import json
import os
sys.path.append("../Reverse-Tools/Common/")
sys.path.append("../Reverse-Tools/CxxParser/")
import Itanium
import Common
import x86_64
import Parser
import Lexer
idaapi.require("Itanium")
idaapi.require("Common")
idaapi.require("x86_64")
idaapi.require("Lexer")
idaapi.require("Parser")

# This needs to do an initial pass and fill in the spaces which we defintely know there is only 1 symbol
# From there we can do another pass using the set of remaining virtual symbols for the class to see if we can get anymore
# After that pass, check for any classes which inherit out class and see if they override the function we are looking at
# We can also do an overlap check between the functions remaining in our class set and the ones in that other classes set
# to help rule out more options. To do that we need a function to get all the possible choices for a vtable entry
# rather than returning None, we return a set and keep checking inherited classes until either our set has 1 entry
# in which case we use that symbol, or last case scenario if we don't find anything through those methods we can fall back onto
# the linux vtable order, although this is not very reliable for some classes with overloads being split.

tools_folder = os.path.join(os.environ.get("amethyst"), "tools")
targets = Common.load_json(os.path.join(tools_folder, "header_targets.json"))
win_server_data = Common.load_json(os.path.join(tools_folder, "server_symbols.json"))
linux_server_data = Common.load_json(os.path.join(tools_folder, "inheritance.json"))

names = dict(idautils.Names())
windows_vtables = []
loaded_data = {}

def try_get_virtual_directly(class_name, v_index):
    vtable_ea = x86_64.get_vtable_by_name(windows_vtables, class_name)
    if not vtable_ea: return None
     
    vtable_entries = x86_64.get_vtable_entries(names, vtable_ea)
    
    address = vtable_entries[v_index]
    symbols = win_server_data["address_to_symbols"][str(address)]
    filtered_symbols = []
    
    # Only look for symbols that are virtual and can be demangled
    for symbol in symbols:
        demangled_name: str | None = idaapi.demangle_name(symbol, 0)
        if not demangled_name: continue
        
        if "virtual " in demangled_name and f"@{class_name}@@" in symbol:
            filtered_symbols.append(symbol)
            
    # If we are down to 1 symbol, return that
    if len(filtered_symbols) == 1: return filtered_symbols[0]
    
    # Else check for any classes which override the function and use that to find a name
    # for child_class in linux_server_data["dependencies"][class_name]:
    #     child_symbol = try_get_virtual_directly(child_class, v_index)
    #     if child_symbol: return child_symbol
    
    return None
    

# Vtable names need to be loaded externally, IDA can only read one symbol for an address.
# Read the data and reformat slightly to be easier to work with.
for vtable in win_server_data["vtables"]:
    windows_vtables.append((vtable["address"], vtable["symbol"], vtable["demangled"]))

print(f"Loaded {len(windows_vtables)} vtables")

found = 0
total = 0

# Read in any data needed and store the information needed for each file
for target in targets:
    file_path = target.get("filepath")
    classes = target.get("classes")
    
    loaded_data[file_path] = []
    
    for class_name in classes:
        windows_vtable_ea = x86_64.get_vtable_by_name(windows_vtables, class_name)
        windows_vtable_entries = x86_64.get_vtable_entries(names, windows_vtable_ea)
        
        windows_vtable = []
        for (index, func_ea) in enumerate(windows_vtable_entries):
            total += 1
            direct_symbol = try_get_virtual_directly(class_name, index)
            print(direct_symbol)
            
            if direct_symbol is not None:
                found += 1
                
print(f"Found {found} out of {total}")