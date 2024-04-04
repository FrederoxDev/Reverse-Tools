from typing import List
import idaapi
import idautils 
import ida_name
import idc
import sys
sys.path.append("../Reverse-Tools/CxxParser/")
sys.path.append("../Reverse-Tools/Common/")
import Itanium

targets = [
    {
        "path": "src/common/world/level/BlockSource.hpp",
        "class_name": "BlockSource"
    }
]

linux_vtables = Itanium.get_vtables()        
print(f"Loaded {len(linux_vtables)} vtables.")

for (ea, name) in linux_vtables:
    if "`vtable for'BlockSource" == name:
        print(ea, name)