from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import os.path


#Encryption Function
def tripleDes_file_encrypt(file_name, key,save_path):
    key = key.encode('utf-8')
    key = pad(key, DES3.block_size)
    with open (file_name,'rb') as entry:
        data = entry.read()
        cipher = DES3.new(key, DES3.MODE_CFB)
        ciphertext =  cipher.encrypt(pad(data, DES3.block_size))
        iv = b64encode(cipher.iv).decode('utf-8')
        ciphertext = b64encode(ciphertext).decode('utf-8')
        to_write = iv + ciphertext
    entry.close()
    with open(os.path.join(save_path,file_name+'.enc'),'w') as data:
        data.write(to_write)
    print("Data has been encrypted.")
    data.close()

#Decryption function
def tripleDes_file_decrypt(file_name,key,save_path):
    key = key.encode('utf-8')
    key = pad(key, DES3.block_size)
    with open (file_name,'r') as entry:
        try:
            data = entry.read()
            length = len(data)
            iv = data[:24]
            iv = b64decode(iv)
            ciphertext = data[24:length]
            ciphertext = b64decode(ciphertext)
            cipher = DES3.new(key, DES3.MODE_CFB,iv)
            decrypted = cipher.decrypt(ciphertext)
            decrypted = unpad(decrypted, DES3.block_size)
            with open(os.path.join(save_path+os.path.basename(file_name[:-4])), 'wb') as data:
                data.write(decrypted)
            print("Data has been Decryption.")
            data.close()
        except(ValueError, KeyError):
            print('wrong password')


print('1. Encrypt File with DES3')
print('2. Decrypt File with DES3')
num = input('===>>> ')
num = int(num)
if num == 1:
    file_name = input('Enter Path of File: ')
    key = input('Enter Key for Encryption: ')
    save_path = input('Enter save path of file encrypted: ')
    tripleDes_file_encrypt(file_name,key,save_path)
    print('Your File has been Encryption!!!')
elif num == 2:
    file_name = input('Enter Path of File: ')
    key = input('Enter Key for Decryption: ')
    save_path = input('Enter save path of file decrypted: ')
    tripleDes_file_decrypt(file_name, key, save_path)
else:
    print('Please Input Number above')

#Input data
# -Path of file stored
# -Key Encryption
# -Block Cipher Mode
# ---------To do--------------
# -Encryption File using DES3
# - Cupture time Comsumming of algorithm.