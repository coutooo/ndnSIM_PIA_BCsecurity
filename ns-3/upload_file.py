import os
import hashlib
import json
import requests
import datetime
import argparse

class MerkleTree:
    def __init__(self):
        self.leaves = []

    def add(self, data):
        leaf = hashlib.sha256(data.encode()).hexdigest()
        self.leaves.append(leaf)

    def get_root(self):
        if len(self.leaves) == 0:
            return None
        if len(self.leaves) == 1:
            return self.leaves[0]

        tree = self.leaves.copy()
        while len(tree) > 1:
            tree = self.compute_next_level(tree)
        return tree[0]

    def compute_next_level(self, level):
        next_level = []
        i = 0
        while i < len(level):
            left_child = level[i]
            right_child = level[i + 1] if i + 1 < len(level) else level[i]
            parent = self.compute_parent_hash(left_child, right_child)
            next_level.append(parent)
            i += 2
        return next_level

    def compute_parent_hash(self, left_child, right_child):
        return hashlib.sha256((left_child + right_child).encode()).hexdigest()

def search_manifest_file(folder_path, filename):
    abs_folder_path = os.path.abspath(folder_path)

    def search_files(current_path):
        files = os.listdir(current_path)
        for file in files:
            file_path = os.path.join(current_path, file)
            file_stat = os.stat(file_path)
            if os.path.isdir(file_path):
                sub_folder_path = os.path.join(current_path, file)
                result = search_files(sub_folder_path)
                if result:
                    return result
            elif file == filename:
                return file_path
        return None

    return search_files(abs_folder_path)

def read_file_chunks(file_path, chunk_size, indexed_hashes, filename):
    with open(file_path, 'rb') as file_data:
        file_data = file_data.read()
        file_size = len(file_data)
        chunks = []
        offset = 0
        chunk_index = 1

        output_dir = os.path.join(os.path.dirname(__file__), 'producer_files')
        os.makedirs(output_dir, exist_ok=True)  # Create the output directory if it doesn't exist

        while offset < file_size:
            chunk = file_data[offset:offset + chunk_size]
            chunks.append(chunk)

            file_extension = os.path.splitext(filename)[-1]
            chunk_filename = f'{filename.split(file_extension)[0]}#{chunk_index}{file_extension}'
            indexed_hashes[f'chunk_{chunk_index}'] = chunk_filename
            chunk_file_path = os.path.join(output_dir, chunk_filename)
            
            with open(chunk_file_path, 'wb') as chunk_file:
                chunk_file.write(chunk)

            offset += chunk_size
            chunk_index += 1

        return chunks

def save_file_chunks(chunks, output_dir, indexed_hashes):
    for i, chunk in enumerate(chunks):
        chunk_hash = indexed_hashes.get(f'chunk_{i}', '')
        chunk_file_path = os.path.join(output_dir, chunk_hash)
        with open(chunk_file_path, 'wb') as chunk_file:
            chunk_file.write(chunk)

def upload_file(file_path, comment):
    filename = os.path.basename(file_path)
    file_contents = open(file_path, 'rb').read().decode('utf-8')
    file_hash = hashlib.sha256(file_contents.encode()).hexdigest()

    file_size = len(file_contents)
    chunk_size = 1024
    num_chunks = (file_size + chunk_size - 1) // chunk_size

    indexed_hashes = {}

    leaves = []
    merkle_tree = MerkleTree()

    for i in range(0, len(file_contents), chunk_size):
        chunk = file_contents[i:i + chunk_size]
        chunk_hash = hashlib.sha256(chunk.encode()).hexdigest()
        leaves.append(chunk_hash)
        chunk_index = i // chunk_size + 1

        file_extension = os.path.splitext(filename)[-1]
        chunk_filename = f'{filename.split(file_extension)[0]}#{chunk_index}{file_extension}'
        indexed_hashes[f'chunk_{chunk_index}'] = chunk_filename

    for leaf in leaves:
        merkle_tree.add(leaf)

    root = merkle_tree.get_root()

    manifest = {
        'nome_ficheiro': filename,
        'merkle_tree': root,
        'assinatura_do_ficheiro': file_hash,
        'numero_de_chunks': num_chunks,
        'tamanho_dos_chunks': chunk_size,
        'comentario': comment,
        'chunks_hashs': indexed_hashes
    }

    manifest['timestamp'] = datetime.datetime.now().isoformat()

    manifest_filename = f'manifest_{filename}'
    manifest_path = os.path.join(os.path.dirname(__file__), 'manifests', manifest_filename)

    with open(manifest_path, 'w') as manifest_file:
        json.dump(manifest, manifest_file)

    read_file_chunks(file_path, chunk_size, indexed_hashes, filename)

    text = f'cityinfo send "{json.dumps(manifest)}" forum'
    response = requests.post('http://localhost:8080/execute', headers={'Content-Type': 'application/json'}, data=json.dumps({'text': text}))

    return 'File uploaded successfully'

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Upload a file with a comment')
    parser.add_argument('file_path', help='Path to the file to upload')
    parser.add_argument('comment', help='Comment for the file')

    args = parser.parse_args()

    file_path = args.file_path
    comment = args.comment

    result = upload_file(file_path, comment)
    print(result)
