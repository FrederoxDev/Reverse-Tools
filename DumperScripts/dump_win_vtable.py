import idaapi
import idautils 
import ida_name
import idc
import sys
sys.path.append("../Reverse-Tools/Common/")
import x86_64
import Common
import os
import time
import re
idaapi.require("x86_64")
idaapi.require("Common")

tools_folder = os.path.join(os.environ.get("amethyst"), "tools")
win_server_data = Common.load_json(os.path.join(tools_folder, "server_symbols.json"))

vtable_pattern = re.compile(r'const (.*?)::`vftable\'')
vector_destructor = re.compile(r'\?\?_E(.*?)@@')
symbol_pattern = re.compile(r'@(.*?)@@')

windows_vtables = {}
names = dict(idautils.Names())

def get_virtual_func_set(class_name):
    virtual_set = set()
    
    for address in win_server_data["address_to_symbols"]:
        for symbol in win_server_data["address_to_symbols"][address]: 
            if not f"{class_name}@@" in symbol: continue
            
            demangled: str | None = idaapi.demangle_name(symbol, 0)
            if demangled == None: continue
            if not "virtual " in demangled: continue
            
            if f"@{class_name}@@" in symbol:
                virtual_set.add(symbol)
            
            # `vector deleting destructor'
            elif symbol.startswith(f"??_E{class_name}@@"):
                virtual_set.add(symbol)
            
    return virtual_set

start = time.time()

virtual_sets = {}

for address in win_server_data["address_to_symbols"]:
    for symbol in win_server_data["address_to_symbols"][address]:
        symbol: str
        
        if symbol.startswith("?$"): continue
        
        demangled: str | None = idaapi.demangle_name(symbol, 0)
        if demangled == None: continue
        if not "virtual " in demangled: continue
        
        # `vector deleting destructor'
        if symbol.startswith("??_E"):
            match = vector_destructor.search(symbol)
            if not match: continue
            
            if match.group(1).startswith("?$"): continue
            
            if not match.group(1) in virtual_sets:
                virtual_sets[match.group(1)] = set()
                
            virtual_sets[match.group(1)].add(symbol)
            continue
        
        match = symbol_pattern.search(symbol)
        if not match: continue
        
        if match.group(1).startswith("?$"): continue
        
        if not match.group(1) in virtual_sets:
            virtual_sets[match.group(1)] = set()
            
        virtual_sets[match.group(1)].add(symbol)


for vtable in win_server_data["vtables"]:
    match = vtable_pattern.search(vtable["demangled"])
    vtable_ea = vtable["address"]
    entries = x86_64.get_vtable_entries(names, vtable_ea)
    matched_set = []
    
    if not match: continue
    
    if match.group(1) in virtual_sets:
        matched_set = list(virtual_sets[match.group(1)])

    windows_vtables[match.group(1)] = {
        "vtable_ea": vtable_ea,
        "entries": entries,
        "virtual_symbol_set": matched_set
    }
        
time_elapsed = time.time() - start

print(f"Dumped vtables in {time_elapsed} seconds")
Common.write_json(os.path.join(tools_folder, "windows_vtable.json"), windows_vtables)