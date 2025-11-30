import os
import re
import time

counter = 0
start_time = time.time()

def replacement_function(match):
    global counter
    counter += 1
    return 'Libg.offset(0x0, 0x0)'

def replace_offsets_in_file(file_path):
    global counter

    with open(file_path, 'r', encoding='utf-8') as file: content = file.read()

    pattern = r'Libg\.offset\(\s*(-?0x[0-9A-Fa-f]+|-?\d+)\s*,\s*(-?0x[0-9A-Fa-f]+|-?\d+)\s*\)'

    replaced_content = re.sub(pattern, replacement_function, content)

    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(replaced_content)

def process_directory(directory):
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.ts'):
                file_path = os.path.join(root, file)
                replace_offsets_in_file(file_path)

src_directory = '../src'
process_directory(src_directory)

print(f'Done. Removed {counter} offsets in {time.time() - start_time} seconds.')
