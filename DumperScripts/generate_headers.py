from typing import List
import idaapi
import idautils 
import ida_name
import idc
import sys
import json
import os
sys.path.append("../Reverse-Tools/Common/")
sys.path.append("../Reverse-Tools/CxxParser/")
import Itanium
import Common
import x86_64
import Parser
import Lexer
import time
import re
idaapi.require("Itanium")
idaapi.require("Common")
idaapi.require("x86_64")
idaapi.require("Lexer")
idaapi.require("Parser")

# print("Wrong script dumbo")
# exit(1)

# This needs to do an initial pass and fill in the spaces which we defintely know there is only 1 symbol
# From there we can do another pass using the set of remaining virtual symbols for the class to see if we can get anymore
# We repeat this pass until a pass makes 0 changes.

# After that pass, check for any classes which inherit out class and see if they override the function we are looking at
# We can also do an overlap check between the functions remaining in our class set and the ones in that other classes set
# to help rule out more options. To do that we need a function to get all the possible choices for a vtable entry
# rather than returning None, we return a set and keep checking inherited classes until either our set has 1 entry
# in which case we use that symbol, or last case scenario if we don't find anything through those methods we can fall back onto
# the linux vtable order, although this is not very reliable for some classes with overloads being split.

start = time.time()
tools_folder = os.path.join(os.environ.get("amethyst"), "tools")
targets = Common.load_json(os.path.join(tools_folder, "header_targets.json"))
win_server_data = Common.load_json(os.path.join(tools_folder, "server_symbols.json"))
linux_server_data = Common.load_json(os.path.join(tools_folder, "inheritance.json"))

names = dict(idautils.Names())
windows_vtables = {}
loaded_data = {}

def get_virtual_func_set(class_name):
    virtual_set = set()
    
    for address in win_server_data["address_to_symbols"]:
        for symbol in win_server_data["address_to_symbols"][address]: 
            if not f"{class_name}@@" in symbol: continue
            
            demangled: str | None = idaapi.demangle_name(symbol, 0)
            if demangled == None: continue
            if not "virtual " in demangled: continue
            
            if f"@{class_name}@@" in symbol:
                virtual_set.add(symbol)
            
            # `vector deleting destructor'
            elif symbol.startswith(f"??_E{class_name}@@"):
                virtual_set.add(symbol)
            
    return virtual_set

time_in_get_vtable_entries = 0

def direct_pass(class_name, windows_vtable_ea):
    if windows_vtable_ea == None:
        return None
    
    start = time.time()
    windows_vtable_entries = x86_64.get_vtable_entries(names, windows_vtable_ea)
    
    global time_in_get_vtable_entries
    time_in_get_vtable_entries += time.time() - start    
        
    # Make a set of all possible options
    # Iterate through each entry and check for symbols with 1 match
    # Keep doing passes through until a pass is made with 0 changes
    vtable_set = get_virtual_func_set(class_name)
        
    # (Found, set options)
    final_vtable = [(False, None)] * len(windows_vtable_entries) 
        
    while True:
        made_changes_this_pass = False
            
        for (index, ea) in enumerate(windows_vtable_entries):                
            # If the symbol has already been found skip
            if final_vtable[index][0]: continue
            
            options = set(win_server_data["address_to_symbols"][str(ea)])
            intersection = options & vtable_set
                
            if len(intersection) == 1:
                choice = list(intersection)[0]
                vtable_set.remove(choice)
                    
                final_vtable[index] = (True, intersection)
                made_changes_this_pass = True
                    
            else:
                final_vtable[index] = (False, intersection)
            
        # Nothing changed this pass so move onto the next steps
        if not made_changes_this_pass:
            break    
            
        count = 0
        for (found, _) in final_vtable:
            if found: count += 1
            
        print(f"Direct Pass for {class_name}: {count} / {len(final_vtable)}")
        
    return {
        "remaining_set": vtable_set,
        "final_vtable": final_vtable
    }

def propagate_down(child_class_name: str, child_symbol: str, class_name: str, class_options: list):
    unnamed_symbol = child_symbol.replace(f"@{child_class_name}@@", "@", 1)
    
    for opt in class_options:
        unnamed_class_symbol = opt.replace(f"@{class_name}@@", "@", 1)
        
        if unnamed_symbol == unnamed_class_symbol:
            return opt
        
    return None

def get_vtable_by_name(class_name):
    if class_name in windows_vtables:
        return windows_vtables[class_name]
    
    return None

# Vtable names need to be loaded externally, IDA can only read one symbol for an address.
# Read the data and reformat slightly to be easier to work with.
pattern = re.compile(r'const (.*?)::`vftable\'')

for vtable in win_server_data["vtables"]:
    match = pattern.search(vtable["demangled"])
    if match:
        windows_vtables[match.group(1)] = vtable["address"]

results = {}

# Read in any data needed and store the information needed for each file
for target in targets:
    file_path = target.get("filepath")
    classes = target.get("classes")
    
    for class_name in classes:
        searched_vtables = set()
        vtable_ea = get_vtable_by_name(class_name)
        
        if class_name not in results:
            results[class_name] = direct_pass(class_name, vtable_ea)
            searched_vtables.add(vtable_ea)
            
        # This class does not have a vtable!
        if results[class_name] is None: continue
        
        # Look at the classes which extend our class and see if they override any functions we don't have yet.
        dependant_classes = linux_server_data["dependencies"][class_name]
        
        for dependant_class in dependant_classes:
            # This dependant class has already been done before
            if dependant_class in results: continue
            
            dependant_vtable_ea = get_vtable_by_name(dependant_class)
            
            # Another class uses the exact same vtable, skip trying again.
            if dependant_vtable_ea in searched_vtables:
                continue
            
            results[dependant_class] = direct_pass(dependant_class, dependant_vtable_ea)
            searched_vtables.add(dependant_vtable_ea)
            
        # Propagate symbols.
        # for dependant_class in dependant_classes:
        #     if dependant_class is None: continue
        #     if not dependant_class in results: continue
        #     if results[dependant_class] is None: continue
            
        #     for (index, entry) in enumerate(results[dependant_class]["final_vtable"]):
        #         # Check we are in the bounds of our vtable
        #         if index > len(results[class_name]["final_vtable"]) - 1: break
        #         matching_entry = results[class_name]["final_vtable"][index]
                
        #         # Neither of the classes have found what we are looking for
        #         if not entry[0] and not matching_entry[0]: continue
                
        #         # Propagate the symbol upwards.
        #         elif matching_entry[0] == True: 
        #             results[dependant_class]["final_vtable"][index] = matching_entry
                    
        #         # Progagate the symbol downwards.
        #         elif entry[0] == True:
        #             result = propagate_down(dependant_class, list(entry[1])[0], class_name, list(matching_entry[1]))
                    
        #             if result is not None:
        #                 results[class_name]["final_vtable"][index] = [True, set([result])]        
            
Common.write_json(os.path.join(tools_folder, "res.json"), results)
elapsed = time.time() - start

print(elapsed)
print(f"time in get vtable entries: {time_in_get_vtable_entries}")