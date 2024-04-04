import idaapi
import idautils 
import ida_name
import idc
import os
import json
        
def load_json(file_path):
    if not os.path.exists(file_path):
        raise Exception(f"Tried to read file '{file_path}' but it does not exist.")
    
    with open(file_path, "r") as file:
        return json.loads(file.read())
