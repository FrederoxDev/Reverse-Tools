from typing import List
from itanium_demangler import parse, Node, FuncNode
import idautils 
import idaapi
import idautils 
import ida_name
import idc

class ItaniumParser:
    func: FuncNode
    symbol: str
    
    def __init__(self, symbol) -> None:
        self.symbol = symbol
        self.func = parse(symbol)
        
    def args(self):
        for arg in self.func.arg_tys:
            print(arg)
            
    def name(self) -> List[str]:
        names: Node = self.func.name[1]
        r = []
        
        for name in names:
            name: Node
            r.append(str(name))
            
        return r
    
# Pass dict(idautils.Names()) as the first parameter. It only needs to be determined once.
def get_vtable_entries(names, vtable_ea: int):
    _, _, pos = ida_name.NearestName(names).find(vtable_ea)
    last_entry_ea = list(names.keys())[pos + 1] - 8
    
    entries = []
    
    for address in range(vtable_ea + 16, last_entry_ea, 8):
        ea = idc.get_qword(address)
        entries.append(ea)

    return entries
 
# Pass idautils.Names() as the first parameter. It only needs to be determined once.
def get_vtables() -> List[tuple[int, str, str]]:
    vtables = []
    
    for (address, mangled_name) in idautils.Names():
        mangled_name: str
        if mangled_name.startswith("_ZTV"):
            demangled_name: str | None = idaapi.demangle_name(mangled_name, 0)
            
            if demangled_name == None:
                continue
            
            if not "`vtable" in demangled_name:
                raise Exception("Expected to only find vtables.")
            
            vtables.append((address, mangled_name, demangled_name))
            
    return vtables