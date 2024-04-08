import idaapi
import ida_name
import idc
import sys
sys.path.append("../Reverse-Tools/Common/")
import Itanium
idaapi.require("Itanium")

def get_typeinfo(typeinfo_ea):
    type_info_rtti_class = idc.get_qword(typeinfo_ea)
    mangled_rtti_type = ida_name.get_name(type_info_rtti_class - 16)  
    rtti_type: str | None = idaapi.demangle_name(mangled_rtti_type, 0)
    
    if rtti_type == None:
        return None
    
    # The class does not inherit anything
    # class name: +8
    if rtti_type == "`vtable for'__cxxabiv1::__class_type_info":
        name_ea = idc.get_qword(typeinfo_ea + 8)
        
        return {
            "inheritance_type": "none",
            "name": Itanium.read_type_name(name_ea)
        }
        
    # The class inherits one thing
    # class name : +8
    # parent type: +16
    elif rtti_type == "`vtable for'__cxxabiv1::__si_class_type_info":
        name_ea = idc.get_qword(typeinfo_ea + 8)
        parent_ea = idc.get_qword(typeinfo_ea + 16)
        
        return {
            "inheritance_type": "single",
            "name": Itanium.read_type_name(name_ea),
            "parent": get_typeinfo(parent_ea)
        }
        
    # The class inherits from multiple things at once
    # class name (8B):                          +8
    # count_of_base_classes(4B), attribute(4B): +16
    elif rtti_type == "`vtable for'__cxxabiv1::__vmi_class_type_info":
        name_ea = idc.get_qword(typeinfo_ea + 8)
        base_class_count = (idc.get_qword(typeinfo_ea + 16) & 0xFFFFFFFF00000000) >> 32
        attribute = idc.get_qword(typeinfo_ea + 16) & 0x00000000FFFFFFFF
        
        base_classes = []
        
        for i in range(base_class_count):
            base_class_ea = typeinfo_ea + 24 + i * 16
            
            base_class = get_typeinfo(idc.get_qword(base_class_ea))
            base_class_attributes = idc.get_qword(base_class_ea + 8)
            
            base_classes.append({
                "base_class": base_class,
                "base_attributes": base_class_attributes
            })
            
        return {
            "inheritance_type": "multiple",
            "name": Itanium.read_type_name(name_ea),
            "attribute": attribute,
            "base_classes": base_classes
        }
    
    else:
        raise Exception(f"Unexpected RTTI Type {rtti_type}")
    
def is_class_a_parent(typeinfo, class_name, dependencies_set: set):
    type = typeinfo["inheritance_type"]
    name = typeinfo["name"]
    
    if name == class_name:
        return True
    
    if type == "single":
        if is_class_a_parent(typeinfo["parent"], class_name, dependencies_set):
            dependencies_set.add(name)
            return True
        
    if type == "multiple":
        for base in typeinfo["base_classes"]:
            if is_class_a_parent(base["base_class"], class_name, dependencies_set):
                dependencies_set.add(name)
                return True
            
    return False