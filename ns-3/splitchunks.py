import os
import sys

def split_and_rename_file(input_file, output_directory, chunk_size):
    with open(input_file, 'rb') as file:
        data = file.read(chunk_size)
        chunk_number = 1
        while data:
            output_file = os.path.join(output_directory, f"{os.path.splitext(input_file)[0]}#{chunk_number}{os.path.splitext(input_file)[1]}")
            with open(output_file, 'wb') as output:
                output.write(data)
            data = file.read(chunk_size)
            chunk_number += 1

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Usage: python script.py input_file output_directory chunk_size")
        sys.exit(1)

    input_file = sys.argv[1]
    output_directory = sys.argv[2]
    chunk_size = int(sys.argv[3])

    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    split_and_rename_file(input_file, output_directory, chunk_size)









