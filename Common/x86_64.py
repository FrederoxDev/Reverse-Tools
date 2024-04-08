from typing import List
from itanium_demangler import parse, Node, FuncNode
import idautils 
import idaapi
import idautils 
import ida_name
import idc

def get_vtables() -> List[tuple[int, str, str]]:
    vtables = []
    
    for (address, mangled_name) in idautils.Names():
        mangled_name: str
        
        demangled_name: str | None = idaapi.demangle_name(mangled_name, 0)
            
        if demangled_name == None:
            continue
            
        if not "`vftable'" in demangled_name:
            continue
            
        vtables.append((address, mangled_name, demangled_name))
            
            
    return vtables

# Pass dict(idautils.Names()) as the first parameter. It only needs to be determined once.
def get_vtable_entries(names, vtable_ea: int):
    _, _, pos = ida_name.NearestName(names).find(vtable_ea)
    last_entry_ea = list(names.keys())[pos + 1]
    
    entries = []
    
    for address in range(vtable_ea, last_entry_ea, 8):
        ea = idc.get_qword(address)
        entries.append(ea)

    return entries

def get_vtable_by_name(all_vtables, target_name):
    for (vtable_ea, _, name) in all_vtables:
        if name == f"const {target_name}::`vftable'":
            return vtable_ea
        
    return None