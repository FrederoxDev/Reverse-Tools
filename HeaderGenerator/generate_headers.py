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
import x86_64
idaapi.require("Itanium")
idaapi.require("Common")
idaapi.require("x86_64")
from pygccxml import utils
from pygccxml import declarations
from pygccxml import parser
idaapi.require("pygccxml")

# Find the location of the xml generator (castxml or gccxml)
generator_path, generator_name = utils.find_xml_generator()

# Configure the xml generator
xml_generator_config = parser.xml_generator_configuration_t(
    xml_generator_path=generator_path,
    xml_generator=generator_name)

# Write a string containing some c++ code
code = """
    class MyClass {
        int a;
    };
"""

# Parse the code
decls = parser.parse_string(code, xml_generator_config)

# Get access to the global namespace
global_ns = declarations.get_global_namespace(decls)

# r = CppHeaderParser.CppHeader("class Block;")
# print(r)

# test = ["_ZN11BlockSourceD2Ev",
#         "_ZN11BlockSourceD0Ev",
#         "_ZNK11BlockSource8getBlockEiii",
#         "_ZNK11BlockSource8getBlockERK8BlockPos",
#         "_ZNK11BlockSource8getBlockERK8BlockPosj",
#         "_ZNK11BlockSource14getBlockEntityERK8BlockPos",
#         "_ZNK11BlockSource13getExtraBlockERK8BlockPos",
#         "_ZNK11BlockSource14getLiquidBlockERK8BlockPos",
#         "_ZNK11BlockSource8hasBlockERK8BlockPos",
#         "_ZNK11BlockSource17containsAnyLiquidERK4AABB",
#         "_ZNK11BlockSource16containsMaterialERK4AABB12MaterialType",
#         "_ZNK11BlockSource12isUnderWaterERK4Vec3RK5Block",
#         "_ZNK11BlockSource11getMaterialERK8BlockPos",
#         "_ZNK11BlockSource11getMaterialEiii",
#         "_ZNK11BlockSource14hasBorderBlockE8BlockPos",
#         "_ZNK11BlockSource10getChunkAtERK8BlockPos",
#         "_ZNK11BlockSource11hasChunksAtERK6Boundsb",
#         "_ZNK11BlockSource11hasChunksAtERK8BlockPosib",
#         "_ZNK11BlockSource11hasChunksAtERK4AABBb",
#         "_ZNK11BlockSource14getDimensionIdEv",
#         "_ZNK11BlockSource10fetchAABBsERNSt3__16vectorI4AABBNS0_9allocatorIS2_EEEERKS2_b",
#         "_ZNK11BlockSource20fetchCollisionShapesERNSt3__16vectorI4AABBNS0_9allocatorIS2_EEEERKS2_b12optional_refIK26GetCollisionShapeInterfaceEPS5_",
#         "_ZNK11BlockSource29fetchCollisionShapesAndBlocksERNSt3__16vectorIN18BlockSourceVisitor14CollisionShapeENS0_9allocatorIS3_EEEERK4AABBb12optional_refIK26GetCollisionShapeInterfaceEPNS1_IS8_NS4_IS8_EEEE",
#         "_ZNK11BlockSource24getTallestCollisionShapeERK4AABBPfb12optional_refIK26GetCollisionShapeInterfaceE",
#         "_ZNK11BlockSource13getBrightnessERK8BlockPos",
#         "_ZN11BlockSource10getWeakRefEv",
#         "_ZN11BlockSource11addListenerER19BlockSourceListener",
#         "_ZN11BlockSource14removeListenerER19BlockSourceListener",
#         "_ZN11BlockSource13fetchEntitiesEPK5ActorRK4AABBbb",
#         "_ZN11BlockSource13fetchEntitiesE9ActorTypeRK4AABBPK5ActorNSt3__18functionIFbPS4_EEE",
#         "_ZN11BlockSource8setBlockERK8BlockPosRK5BlockiPK21ActorBlockSyncMessageP5Actor",
#         "_ZNK11BlockSource12getMinHeightEv",
#         "_ZNK11BlockSource12getMaxHeightEv",
#         "_ZNK11BlockSource12getDimensionEv",
#         "_ZNK11BlockSource17getDimensionConstEv",
#         "_ZN11BlockSource12getDimensionEv",
#         "_ZNK11BlockSource8getChunkEii",
#         "_ZNK11BlockSource8getChunkERK8ChunkPos",
#         "_ZN11BlockSource8getLevelEv",
#         "_ZNK11BlockSource9getILevelEv",
#         "_ZN11BlockSource10fetchAABBsERK4AABBb",
#         "_ZN11BlockSource20fetchCollisionShapesERK4AABBbNSt3__18optionalIK13EntityContextEEPNS3_6vectorIS0_NS3_9allocatorIS0_EEEE",
#         "_ZNK11BlockSource4clipERK4Vec3S2_b9ShapeTypeibbP5ActorRKNSt3__18functionIFbRKS_RK5BlockbEEE",
#         "_ZN11BlockSource14getChunkSourceEv",
#         "_ZNK11BlockSource20isSolidBlockingBlockERK8BlockPos",
#         "_ZNK11BlockSource20isSolidBlockingBlockEiii",
#         "_ZNK11BlockSource20areChunksFullyLoadedERK8BlockPosi",
#         "_ZNK11BlockSource15canDoBlockDropsEv",
#         "_ZNK11BlockSource23canDoContainedItemDropsEv"
# ]

# Itanium.convert_to_win_order(test)
exit()

tools_folder = os.path.join(os.environ.get("amethyst"), "tools")
targets = Common.load_json(os.path.join(tools_folder, "header_targets.json"))
linux_vtable_data = Common.load_json(os.path.join(tools_folder, "linux_vtable.json"))
win_server_data = Common.load_json(os.path.join(tools_folder, "server_symbols.json"))

names = dict(idautils.Names())
windows_vtables = []
loaded_data = {}

def try_get_symbol_direct(class_name, func_ea) -> str | None:
    symbols = win_server_data["address_to_symbols"][str(func_ea)]
    filtered_symbols = []
    
    for symbol in symbols:
        demangled_name: str | None = idaapi.demangle_name(symbol, 0)
        if not demangled_name:
            continue
        
        if "virtual " in demangled_name and f"@{class_name}@@" in symbol:
            filtered_symbols.append(symbol)
        
    if len(filtered_symbols) == 1:
        return filtered_symbols[0]
    
    print("\n--- Failed to match, remaining options: ---")
    for filtered in filtered_symbols:
        print(filtered)
    print("--- end --- \n")
    
    return None

# Vtable names need to be loaded externally, IDA can only read one symbol for an address.
# Read the data and reformat slightly to be easier to work with.
for vtable in win_server_data["vtables"]:
    windows_vtables.append((vtable["address"], vtable["symbol"], vtable["demangled"]))

print(f"Loaded {len(windows_vtables)} vtables")

# Read in any data needed and store the information needed for each file
for target in targets:
    file_path = target.get("filepath")
    classes = target.get("classes")
    
    loaded_data[file_path] = []
    
    for class_name in classes:
        windows_vtable_ea = x86_64.get_vtable_by_name(windows_vtables, class_name)
        windows_vtable_entries = x86_64.get_vtable_entries(names, windows_vtable_ea)
        
        windows_vtable = []
        for func_ea in windows_vtable_entries:
            direct_symbol = try_get_symbol_direct(class_name, func_ea)
            print(direct_symbol)
        
print(json.dumps(loaded_data))