import argparse
import os

# Define the chunk size
chunk_size = 1024  # 1 kilobyte

def split_file(input_file):
    # Check if the input file exists
    if not os.path.exists(input_file):
        print(f"Error: The file '{input_file}' does not exist.")
        return

    # Get the base name of the input file (without the path)
    file_base_name = os.path.basename(input_file)

    # Determine the file extension from the source file
    file_extension = file_base_name.split(".")[-1]

    # Remove the file extension from the base name
    file_base_name = file_base_name[:-(len(file_extension) + 1)]  # +1 for the dot

    # Open the source file for reading
    with open(input_file, "rb") as source_file:
        chunk_number = 1
        while True:
            # Read a chunk of data
            chunk_data = source_file.read(chunk_size)

            # If there's no more data to read, break the loop
            if not chunk_data:
                break

            # Create the chunk file name without the file extension
            chunk_file_name = f"{file_base_name}#{chunk_number}.{file_extension}"

            # Write the chunk data to a separate file
            with open(chunk_file_name, "wb") as chunk_file:
                chunk_file.write(chunk_data)
                print(f"Chunk '{chunk_file_name}' has been saved.")

            chunk_number += 1

    print(f"File '{input_file}' has been split into {chunk_number - 1} chunks.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Split a file into chunks.")
    parser.add_argument("input_file", help="Path to the input file")
    args = parser.parse_args()
    split_file(args.input_file)
