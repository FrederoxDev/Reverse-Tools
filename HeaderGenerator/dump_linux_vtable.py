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
import ida_typeinf

vtables = Itanium.get_vtables()

for (vtable_ea, _, vtable_name) in vtables:
    type_info_ea = idc.get_qword(vtable_ea + 8)
    print(json.dumps(RTTI.get_typeinfo(type_info_ea)) + "\n\n")
    