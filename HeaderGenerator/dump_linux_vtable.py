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
import RTTI
idaapi.require("Itanium")
idaapi.require("Common")
idaapi.require("RTTI")

tools_folder = os.path.join(os.environ.get("amethyst"), "tools")
inheritance_file = os.path.join(tools_folder, "inheritance.json")

print(inheritance_file)

all_vtables = Itanium.get_vtables()
typeinfo = []

for (vtable_ea, _, vtable_name) in all_vtables:
    type_info_ea = idc.get_qword(vtable_ea + 8)
    typeinfo.append(RTTI.get_typeinfo(type_info_ea))
  
# Pre-Computing dependencies  
dependencies = {}
    
for type in typeinfo:
    type_deps = set()
    
    if type == None:
        continue
    
    for other_type in typeinfo:
        if other_type == None:
            continue
        
        RTTI.is_class_a_parent(other_type, type["name"], type_deps)
        
    dependencies[type["name"]] = list(type_deps)

dumped_data = {
    "inheritance_tree": typeinfo,
    "dependencies": dependencies
}
    
print(f"Writing inheritance and vtable data to: \n\t{inheritance_file}")
Common.write_json(inheritance_file, dumped_data)