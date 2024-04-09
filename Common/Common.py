import idaapi
import idautils 
import ida_name
import idc
import os
import json
import ida_bytes    
import ida_nalt        

class SetEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        return json.JSONEncoder.default(self, obj)
        
def load_json(file_path):
    if not os.path.exists(file_path):
        raise Exception(f"Tried to read file '{file_path}' but it does not exist.")
    
    with open(file_path, "r") as file:
        return json.loads(file.read())
    
def write_json(file_path, obj):    
    with open(file_path, "w") as file:
        file.write(json.dumps(obj, indent=4, cls=SetEncoder))

def read_str_from_ea(str_ea) -> str:
    bytes = ida_bytes.get_strlit_contents(str_ea, -1, ida_nalt.STRTYPE_C)
    return bytes.decode("utf-8")