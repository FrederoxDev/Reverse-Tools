struct = [
    # Type, Name, Size (bytes), Offset (bytes)
    ("BurnOdds", "mBurnOdds", 1, 95),
    ("FlameOdds", "mFlameOdds", 1, 94),
    ("bool", "mIsVanilla", 1, 544),
    ("const Material&", "mMaterial", 8, 296),
    ("unsigned short", "mID", 2, 422)
]

is_virtual = True
struct_size = 844

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
        stringified += f"/* this + {padded_offset} */ std::byte padding{padding_index}[{size_count}];\n"
        padding_index += 1
                
    else:
        stringified += f"/* this + {padded_offset} */ {last_item[0]} {last_item[1]};\n"

vtable_offset = 0
if is_virtual:
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