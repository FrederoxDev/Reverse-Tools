import idaapi
import idautils 
import ida_name
import idc
import sys
sys.path.append("../Reverse-Tools/CxxParser/")

for (address, name) in idautils.Names():
    name: str
    if name.startswith("_ZTV"):
        demangled_name: str | None = idaapi.demangle_name(name, 0)
        
        if demangled_name == None:
            continue
        
        if not "`vtable" in demangled_name:
            print(demangled_name)
            
print("Done")