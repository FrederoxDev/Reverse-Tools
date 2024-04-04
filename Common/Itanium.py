from typing import List
from itanium_demangler import parse, Node, FuncNode
import idautils 
import idaapi

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
    
def get_vtables() -> List[tuple[int, str]]:
    vtables = []
    
    for (address, mangled_name) in idautils.Names():
        mangled_name: str
        if mangled_name.startswith("_ZTV"):
            demangled_name: str | None = idaapi.demangle_name(mangled_name, 0)
            
            if demangled_name == None:
                continue
            
            if not "`vtable" in demangled_name:
                raise Exception("Expected to only find vtables.")
            
            vtables.append((address, demangled_name))
            
    return vtables