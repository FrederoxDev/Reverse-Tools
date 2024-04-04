from typing import List
import idaapi
import idautils 
import ida_name
import idc
import sys
import json
import os
sys.path.append("../Reverse-Tools/CxxParser/")
sys.path.append("../Reverse-Tools/Common/")
import Itanium
import Common
idaapi.require("Itanium")
idaapi.require("Common")

names = dict(idautils.Names())
linux_vtables = Itanium.get_vtables()        

out_path = os.environ.get("amethyst") + "/tools/linux_vtable.json"    

vtable_data = {}

for (index, (vtable_ea, vtable_mangled, _)) in enumerate(linux_vtables):
    name = None
    
    # Try parse the vtable name
    try: name = Itanium.ItaniumParser(vtable_mangled).func
    except: continue
    
    if name == None: continue
    
    class_name = str(name[1])
    
    if class_name.startswith("std::"):
        continue
    
    vtable_data[class_name] = []
        
    # Get each function within the vtable        
    for func_ea in Common.get_vtable_entries(names, vtable_ea):
        symbol_name = idc.get_func_name(func_ea)
        vtable_data[class_name].append(symbol_name)     

# Write data out to file
print(f"Dumped {len(vtable_data)} vtables. Saving to {out_path}")
        
with open(out_path, "w") as file:
    file.write(json.dumps(vtable_data, indent=4))