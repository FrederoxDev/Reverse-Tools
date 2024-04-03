#
# A script to dump parameter names
#
import os

print(os.getcwd())

import sys
sys.path.append("../Reverse-Tools/CxxParser/")
from Lexer import Lexer
from Parser import Parser
import Analyser
import idaapi
import ida_funcs
import idautils
import idc
import json
idaapi.require("Analyser")

def get_param_names(func_ea):
    tinfo = idaapi.tinfo_t()
    idaapi.get_tinfo(tinfo, func_ea)

    funcdata = idaapi.func_type_data_t()
    tinfo.get_func_details(funcdata)

    params = []

    try:
        for i in range(tinfo.get_nargs()):
            params.append(str(funcdata[i].name))

    except: 
        pass

    return params


all_functions = idautils.Functions()

target = idaapi.ask_str("Class name", 0, "Class Name")

data = {}

for func_ea in all_functions:
    mangled = idc.get_func_name(func_ea)
    demangled: str | None = idaapi.demangle_name(mangled, 0)
    if demangled is None:
        continue
    
    if target + "::" not in demangled:
        continue
    
    try:
        tokens = Lexer(demangled).tokenise()
        function = Parser(tokens).parse()
        class_name = Analyser.class_name(function)
        
        if class_name != target + "::":
            continue
        
        param_names = get_param_names(func_ea)
        data[demangled] = param_names
        
    except:
        print("Failed", demangled)
        
amethyst_folder = os.environ.get("amethyst") + "/tools/"

with open(amethyst_folder + "param_names.json", "w") as file:
    file.write(json.dumps(data))