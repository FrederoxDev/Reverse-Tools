is_virtual = True
hide_vtable = False
struct_size = 3232

# (Type, Name, Size (in bytes), Offset (in bytes))
struct = [
("MinecraftGame*", "minecraftGame", 8, 200),
("Minecraft*", "minecraft", 8, 208),
("ClientInputHandler*", "inputHandler", 8, 272),
("ItemRenderer*", "itemRenderer", 8, 1360),
("GuiData*", "guiData", 8, 1368),
("mce::Camera", "camera", 512, 624),
("BlockTessellator*", "mBlockTessellator", 8, 1320)
]

struct_layout = [None] * struct_size

if is_virtual:
    struct_layout[:8] = [("uintptr_t**", "vtable")] * 8
    
for var in struct:
    struct_layout[var[3]:var[3] + var[2]] = [(var[0], var[1])] * var[2]

stringified = ""

last_item = None
size_count = 0
start_offset = 0

padding_index = 0

def write_field():
    global stringified
    global padding_index
    
    padded_offset = str(start_offset).ljust(len(str(struct_size)), " ")
    
    if last_item == None:
        stringified += f"/* this + {padded_offset} */ std::byte padding{start_offset}[{size_count}];\n"
        padding_index += 1
                
    else:
        stringified += f"/* this + {padded_offset} */ {last_item[0]} {last_item[1]};\n"

vtable_offset = 0
if is_virtual and hide_vtable:
    vtable_offset = 8

for i in range(vtable_offset, len(struct_layout)):
    current_item = struct_layout[i]
    
    if current_item != last_item or i == vtable_offset:
        if i != vtable_offset:
            write_field()

        last_item = current_item
        size_count = 1
        start_offset = i
        
    else:
        size_count += 1
        
write_field()
    
print(stringified)