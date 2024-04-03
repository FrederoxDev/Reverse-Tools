import os
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

    for i in range(tinfo.get_nargs()):
        try:
            param_name = str(funcdata[i].name)
            if param_name == "":
                param_name = f"a{i + 1}"
                
            params.append(param_name)
            
        except:    
            params.append(f"a{i + 1}")

    return params


all_functions = idautils.Functions()

data = {}

for func_ea in all_functions:
    mangled = idc.get_func_name(func_ea)
    demangled: str | None = idaapi.demangle_name(mangled, 0)
    if demangled is None:
        continue
    
    try:
        tokens = Lexer(demangled).tokenise()
        function = Parser(tokens).parse()
        class_name = Analyser.class_name(function)
        
        # Ensure there is an array for the class
        if not class_name in data:
            data[class_name] = {} 
        
        param_names = get_param_names(func_ea)
        data[class_name][demangled] = param_names
        
    except:
        # print("Failed", demangled)
        pass
        
amethyst_folder = os.environ.get("amethyst") + "/tools/"

print("Finished! Writing data")

with open(amethyst_folder + "param_names.json", "w") as file:
    file.write(json.dumps(data, indent=4))