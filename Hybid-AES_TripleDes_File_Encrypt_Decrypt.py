from Crypto.Cipher import AES, DES3
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import os.path
from hashlib import md5

try:
    import time
    import threading
except Exception as e:
    pass

global queue

class Queue(object):

    def __init__(self):
        self.item = []

    def __str__(self):
        return "{}".format(self.item)

    def __repr__(self):
        return "{}".format(self.item)

    def enque(self, item):
        """
        Insert the elements in queue
        :param item: Any
        :return: Bool
        """
        self.item.insert(0, item)
        return True

    def size(self):
        """
        Return the size of queue
        :return: Int
        """
        return len(self.item)

    def dequeue(self):
        """
        Return the elements that came first
        :return: Any
        """
        if self.size() == 0:
            return None
        else:
            return self.item.pop()

    def peek(self):
        """
        Check the Last elements
        :return: Any
        """
        if self.size() == 0:
            return None
        else:
            return self.item[-1]

    def isEmpty(self):
        """
        Check is the queue is empty
        :return: bool
        """
        if self.size() == 0:
            return True
        else:
            return False

queue = Queue()


def tripleDes_file_encrypt(plain_text, key):
    cipher = DES3.new(key, DES3.MODE_EAX, nonce=b'0')
    ciphertext = cipher.encrypt(plain_text)
    queue.enque(ciphertext)

def tripleDes_file_decrypt(cipher_text, key):
    cipher = DES3.new(key, DES3.MODE_EAX, nonce=b'0')
    plain_text = cipher.decrypt(cipher_text)
    queue.enque(plain_text)


def aes_file_encrypt(plain_text,key):
    cipher = AES.new(key,AES.MODE_CFB)
    ciphertext = cipher.encrypt(plain_text)
    return ciphertext


def aes_file_decrypt(cipher_text, key,iv):
    cipher = AES.new(key,AES.MODE_CFB,iv)
    plain_text = cipher.decrypt(cipher_text)
    return plain_text



def hybrid_AES_3DES_encrypt(file_name,key,save_path):
    key = md5(key.encode('ascii')).digest()
    key = DES3.adjust_key_parity(key)
    print(key)
    with open(file_name, 'rb') as entry:
        data = entry.read()
        length = len(data)/2
        left_length = int(length)
        right_length = int(length)
        if (len(data) % 2 != 0 ):
            left_length = int(length)
            right_length = int(length) + 1
        left_data = data[:left_length]
        right_data = data[right_length:]
        if __name__ == '__main__':
            thread1 = threading.Thread(target= tripleDes_file_encrypt, args =(left_data, key,))
            thread2 = threading.Thread(target= tripleDes_file_encrypt, args=(right_data,key,))
            thread1.start()
            thread2.start()
            thread1.join()
            thread2.join()
            leftCipherText = queue.dequeue()
            rihgtCipherText = queue.dequeue()
            ciphertextFrom3Des= leftCipherText+rihgtCipherText

            #Apply AES encryption 
            cipher = AES.new(key, AES.MODE_CFB)
            ciphertext =  cipher.encrypt(pad(ciphertextFrom3Des, AES.block_size))
            iv = b64encode(cipher.iv).decode('utf-8')
            ciphertext = b64encode(ciphertext).decode('utf-8')
            to_write = iv + ciphertext

    entry.close()
    with open(os.path.join(save_path,file_name+'.enc'),'w') as data:
        data.write(to_write)
    data.close() 
                              
    
def hybrid_AES_3DES_decrypt(file_name,key,save_path):
    key = md5(key.encode('ascii')).digest()
    key = DES3.adjust_key_parity(key)
    with open(file_name,'r') as entry:
        try:

            data = entry.read()
            length = len(data)
            iv = data[:24]
            iv = b64decode(iv)
            ciphertext = data[24:length]
            ciphertext = b64decode(ciphertext)
            cipherTextAfterAes = aes_file_decrypt(ciphertext, key, iv)
            cipherTextAfterAes = unpad(cipherTextAfterAes, AES.block_size)

            length = len(cipherTextAfterAes)/2
            print(length)
            left_length = int(length)
            right_length = int(length)
            if (len(cipherTextAfterAes) % 2 != 0 ):
                left_length = int(length)
                right_length = int(length) + 1
            left_data = cipherTextAfterAes[:left_length]
            right_data = cipherTextAfterAes[right_length:]


            if __name__ == '__main__':
                thread1 = threading.Thread(target= tripleDes_file_decrypt, args=(left_data, key,))
                thread2 = threading.Thread(target= tripleDes_file_decrypt, args=(right_data,key,))
                thread1.start()
                thread2.start()
                thread1.join()
                thread2.join()
                right_plainText = queue.dequeue()
                left_plainText = queue.dequeue()
                #Merge Plain text
                decrypted = right_plainText+left_plainText
                print(decrypted)
            with open(os.path.join(save_path+os.path.basename(file_name[:-4])), 'wb') as data:
                data.write(decrypted)
            print("Data has been Decryption.")
            data.close()    
        except(ValueError, KeyError):
            print('Password wrong')
    
print('1. Encrypt Data with Hybrid_AES_TripleDes')
print('2. Decrypt Data with Hybrid_AES_TripleDes')
num = input('===>>> ')
num = int(num)
if num == 1:
    file_name = input('Enter Path of File: ')
    key = input('Enter Key for Encryption: ')
    save_path = input('Enter save path of file encrypted: ')
    hybrid_AES_3DES_encrypt(file_name,key,save_path)
elif num == 2:
    file_name = input('Enter Path of File: ')
    key = input('Enter Key for Decryption: ')
    save_path = input('Enter save path of file decrypted: ')
    hybrid_AES_3DES_decrypt(file_name,key,save_path)
else:
    print('Please Input Number above')
