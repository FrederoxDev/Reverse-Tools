import json
from typing import List

type_aliases = [
    ("std::__1::", "std::"),
    ("std::__cxx11::", "std::"),
    ("std::basic_string<char, std::char_traits<char>, std::allocator<char>>", "std::string")
]

# Stringifies a type
def type_to_str(parsed):
    if isinstance(parsed, str):
        return parsed
        
    stringified = ""

    if "is_const" in parsed:
        if parsed["is_const"]:
            stringified += "const "

    if "is_unsigned" in parsed:
        if parsed["is_unsigned"]:
            stringified += "unsigned "

    if "namespace" in parsed:
        stringified += parsed["namespace"] 

        if "generics" in parsed:
            if len(parsed["generics"]) != 0:
                generics = list(map(type_to_str, parsed["generics"]))
                stringified += f"<{', '.join(generics)}>"

        stringified += f"::{type_to_str(parsed['type'])}"

        return stringified

    if "name" in parsed:
        if parsed["name"] is not None:
            stringified += type_to_str(parsed['name'])

    if "generics" in parsed:
        if len(parsed["generics"]) != 0:
            generics = list(map(type_to_str, parsed["generics"]))
            stringified += f"<{', '.join(generics)}>"

    if "ptrs_and_const" in parsed:
        for ptr_or_const in parsed["ptrs_and_const"]:
            if ptr_or_const == "const":
                stringified += " const"
                
            else:
                stringified += "*"
        
    if "ref_count" in parsed:
        stringified += "&" * parsed["ref_count"]

    if "call_signature" in parsed:
        if parsed["call_signature"] is None:
            stringified += "()"

        elif len(parsed["call_signature"]) != 0:
            params = list(map(type_to_str, parsed["call_signature"]))
            stringified += f"({', '.join(params)})"

    if "params" in parsed:
        if parsed["params"] is None:
            stringified += "()"

        elif len(parsed["params"]) != 0:
            params = list(map(type_to_str, parsed["params"]))
            stringified += f"({', '.join(params)})"

    return stringified
  
def type_to_raw(parsed):
    if isinstance(parsed, str):
        return parsed
        
    stringified = ""

    if "namespace" in parsed:
        stringified += parsed["namespace"] 

        stringified += f"::{type_to_str(parsed['type'])}"

        return stringified

    if "name" in parsed:
        if parsed["name"] is not None:
            stringified += type_to_str(parsed['name'])

    if "call_signature" in parsed:
        if parsed["call_signature"] is None:
            stringified += "()"

        elif len(parsed["call_signature"]) != 0:
            params = list(map(type_to_str, parsed["call_signature"]))
            stringified += f"({', '.join(params)})"

    if "params" in parsed:
        if parsed["params"] is None:
            stringified += "()"

        elif len(parsed["params"]) != 0:
            params = list(map(type_to_str, parsed["params"]))
            stringified += f"({', '.join(params)})"

    return stringified
    
def return_type(parsed_function) -> str | None:
    if "return_type" in parsed_function:
        if parsed_function["return_type"] is not None:
            return type_to_str(parsed_function["return_type"])
        
    return None

def parameter_types(parsed_function) -> List[str]:    
    # For functions in a namespace   
    if "body" in parsed_function:     
        if "type" in parsed_function["body"]:
            return parameter_types(parsed_function["body"]["type"])
    
    # Still in a namespace or generic, go deeper
    if isinstance(parsed_function["name"], dict):
        return parameter_types(parsed_function["name"])
    
    if parsed_function["params"] == None:
        return []
    
    return list(map(type_to_str, parsed_function["params"]))

def simplify_parameters(parameters: List[str]) -> List[str]:
    new_params = []
    
    for param in parameters:
        simplified = param
        
        for alias in type_aliases:
            simplified = simplified.replace(alias[0], alias[1])
            
        new_params.append(simplified)
        
    return new_params

def function_name(parsed_function) -> str:    
    # For functions in a namespace   
    if "body" in parsed_function:   
        if "type" in parsed_function["body"]:
            return function_name(parsed_function["body"]["type"])
        
        if "name" in parsed_function["body"]:
            return function_name(parsed_function["body"])
    
    # Still in a namespace or generic, go deeper
    if "name" in parsed_function:
        if isinstance(parsed_function["name"], dict):
            return function_name(parsed_function["name"])
        
        return parsed_function["name"]

    return ""

# Not fully implemented, doesn't support generics yet!
def class_name(parsed_function) -> str:
    value = ""
    
    if "body" in parsed_function:
        if "namespace" in parsed_function["body"]:
            return value + class_name(parsed_function["body"])    
        
    if "namespace" in parsed_function:
        value += parsed_function["namespace"] + "::"
        
        if "type" in parsed_function:
            return value + class_name(parsed_function["type"])
        
    if "name" in parsed_function:
        return value + class_name(parsed_function["name"])
        
    return value

def get_all_types_used(parsed_function, classes: set, structs: set, enums: set):
    if "structure_type" in parsed_function:
        if parsed_function["structure_type"] is not None:
            type = parsed_function["structure_type"]
            
            if type == "struct":
                structs.add(type_to_raw(parsed_function))
                
            elif type == "enum":
                enums.add(type_to_raw(parsed_function))
                
            else:
                classes.add(type_to_raw(parsed_function))
                
    print()
    print("parsed_func", parsed_function)
    
    if "body" in parsed_function:
        get_all_types_used(parsed_function["body"], classes, structs, enums)
        
    if "return_type" in parsed_function:
        if parsed_function["return_type"] is not None:
            get_all_types_used(parsed_function["return_type"], classes, structs, enums)
        
    if "params" in parsed_function:
        for param in parsed_function["params"]:
            get_all_types_used(param, classes, structs, enums)
            
    if "generics" in parsed_function:
        for param in parsed_function["generics"]:
            get_all_types_used(param, classes, structs, enums)
            
    if "type" in parsed_function:
        if parsed_function["type"] is not None:
            get_all_types_used(parsed_function["type"], classes, structs, enums)
            
    if "name" in parsed_function:
        if parsed_function["name"] is not None:
            if isinstance(parsed_function["name"], dict):
                get_all_types_used(parsed_function["name"], classes, structs, enums)