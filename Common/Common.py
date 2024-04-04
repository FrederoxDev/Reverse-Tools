import idaapi
import idautils 
import ida_name
import idc

# Pass dict(idautils.Names()) as the first parameter. It only needs to be determined once.
def get_vtable_entries(names, vtable_ea: int):
    _, _, pos = ida_name.NearestName(names).find(vtable_ea)
    last_entry_ea = list(names.keys())[pos + 1] - 8
    
    entries = []
    
    for address in range(vtable_ea + 16, last_entry_ea, 8):
        ea = idc.get_qword(address)
        entries.append(ea)

    return entries
        