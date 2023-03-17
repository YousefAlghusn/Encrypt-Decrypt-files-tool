from django.shortcuts import render

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent.parent


#key = b'\x1cG\xa2U\xf4D\x16\xdaG!\xf8\xb4\x89\xca\xbdb'



chunk_size = 64 * 1024

def generate_AES(request):
    key = os.urandom(16)
    with open('myapp/static/keys/AES_key.key', 'wb') as f:
        f.write(key)

    return JsonResponse({'result':True})

def encrypt_file_AES(file, key):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    
   
    encrypted_file_path = f"{BASE_DIR}\\myapp\\static\\{str(file)}.encrypted"
    
    input_file =  file.open(mode='rb')
    with open(encrypted_file_path, 'wb') as output_file:
        while True:
            chunk = input_file.read(chunk_size)
            if len(chunk) == 0:
                break
            elif len(chunk) % 16 != 0:
                chunk += b' ' * (16 - len(chunk) % 16)
            output_file.write(encryptor.update(chunk))
    
        output_file.write(encryptor.finalize())
    return encrypted_file_path

def decrypt_file_AES(file, key):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    file_name = os.path.splitext(str(file))[0]
    decrypted_file_path = f"{BASE_DIR}\\myapp\\static\\{file_name}"
   
    input_file = file.open(mode='rb')
    with open(decrypted_file_path, 'wb') as output_file:
        while True:
            chunk = input_file.read(chunk_size)
            if len(chunk) == 0:
                break
            output_file.write(decryptor.update(chunk))
    
        output_file.write(decryptor.finalize())
    return decrypted_file_path

#-----------------------------------------------------------

import rsa
import os
from tqdm import tqdm

# Specify the chunk size (in bytes)
CHUNK_SIZE = 53
from django.http import JsonResponse

def encrypt_file(file, public_key_bytes):
    public_key = pickle.loads(public_key_bytes)
    encrypted_file = b''
    ciphertext = file.read()
    num_chunks = (len(ciphertext) + CHUNK_SIZE - 1) // CHUNK_SIZE
    chunks = [ciphertext[i * CHUNK_SIZE: (i + 1) * CHUNK_SIZE] for i in range(num_chunks)]

   
    for chunk in tqdm(chunks):
        encrypted_chunk = rsa.encrypt(chunk, public_key)
        encrypted_file += encrypted_chunk
        

    # Write the encrypted file to disk
    encrypted_file_path = f"{BASE_DIR}\\myapp\\static\\{str(file)}.encrypted_RSA"
    with open(encrypted_file_path, 'wb') as f:
        f.write(encrypted_file)

    return JsonResponse({'completed': True})

def decrypt_file(file, private_key_bytes):
    private_key = pickle.loads(private_key_bytes)
    decrypted_file = b''
    CHUNK_SIZE = 256
    ciphertext = file.read()
    num_chunks = (len(ciphertext) + CHUNK_SIZE - 1) // CHUNK_SIZE
    chunks = [ciphertext[i * CHUNK_SIZE: (i + 1) * CHUNK_SIZE] for i in range(num_chunks)]

    
    for encrypted_chunk in tqdm(chunks):
        # Decrypt the chunk
        decrypted_chunk = rsa.decrypt(encrypted_chunk, private_key)
        decrypted_file += decrypted_chunk

    # Write the decrypted file to disk
    file_name = os.path.splitext(str(file))[0]
    decrypted_file_path = f"{BASE_DIR}\\myapp\\static\\decrypted_{file_name}"
    with open(decrypted_file_path, 'wb') as f:
        f.write(decrypted_file)

    return file_name



import pickle

def generate_RSA(request):
    (public_key, private_key) = rsa.newkeys(2048)
    store_keys(public_key, private_key)
    return JsonResponse({'result':True})

def store_keys(public_key, private_key):
    # Serialize the keys
    public_key_bytes = pickle.dumps(public_key)
    private_key_bytes = pickle.dumps(private_key)

    # Write the serialized keys to disk
    with open('myapp/static/keys/public_key.pem', 'wb') as public_key_file:
        public_key_file.write(public_key_bytes)
    with open('myapp/static/keys/private_key.pem', 'wb') as private_key_file:
        private_key_file.write(private_key_bytes)




def load_keys():
    # Read the serialized keys from disk
    with open(f'{BASE_DIR}\\myapp\\static\\keys\\public_key.pem', 'rb') as public_key_file:
        public_key_bytes = public_key_file.read()
    with open(f'{BASE_DIR}\\myapp\\static\\keys\\private_key.pem', 'rb') as private_key_file:
        private_key_bytes = private_key_file.read()

    # Deserialize the keys
    public_key = pickle.loads(public_key_bytes)
    private_key = pickle.loads(private_key_bytes)

    return (public_key, private_key)

# Load the keys from disk
(public_key, private_key) = load_keys()





def main(request):
    if request.method == 'POST':
        decision = request.POST.get('decision')
        file = request.FILES['file']
        filename = str(file)
        key = request.FILES['key']
        if decision == "AES_enc":
            encrypt_file_AES(file, key.read())
        elif decision == "AES_dec":
            filename = decrypt_file_AES(file, key.read())
        elif decision == "RSA_enc":
            encrypt_file(file, key.read())
        elif decision == "RSA_dec":
            filename = decrypt_file(file, key.read())
            
            

        #print(len(file.read()))
        #encrypt_file(file, public_key)
        #decrypt_file(file, private_key)
        return render(request,'index.html',{'completed': decision,'filename': filename})
       

        
    return render(request,'index.html',{'completed': "none","filename":"none"})


