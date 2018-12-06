"""
Things to do:
1. check if there is a meta file (of the form '#META#')
"""
import os.path
import getpass
import sys
from Crypto import Random

from Crypto.Cipher import AES
from Crypto.Util import Padding
from Crypto.Util import Counter
from mapping import *

def main():
    print('\n=== Python Password Manager ===\n')
    key = ''
    if is_first_session():
        key = first_session()
    else:
        key = begin_session()
    while(True):
        get_operation()

def first_session():
    print('Welcome. Please enter a secure master password.\nThis password must be at least 10 characters in length.')
    password = 'password' 
    confirm_password = 'confirm'
    while password != confirm_password:
        while len(password) < 10:
            password = getpass.getpass('Master password: ')
            if len(password) < 10:
                print('Master password is less than 10 characters in length.')
        confirm_password = getpass.getpass('Confirm password: ')
        if password != confirm_password:
            print('Passwords do not match.\n')
            password = ''
    # derive key, hash
    # write key hash to file (maybe ??)
    # return key

def begin_session():
    print('Welcome. Please enter your master password.')
    password = getpass.getpass('Master password: ')
    confirm_password = getpass.getpass('Confirm password: ')
    if password != confirm_password:
        print('Passwords do not match.\n')
        quit()
    # derive key, return key

def get_operation():
    cmd = input('Select an operation (add / delete / help / quit / retrieve): ').lower()
    if cmd == 'add':
        add_password()
    elif cmd == 'delete':
        delete_password()
    elif cmd == 'help':
        print_help()
    elif cmd == 'quit':
        print('Goodbye.')
        sys.exit(0)
    elif cmd == 'retrieve':
        retrievePassword()
    else:
        print(cmd + ' is not a recognized command. Try \'help\'.')

# to implement

def is_first_session():
    if os.path.exists('.__META__.'):
        return False
    return True

def write_key_hash(keyHash):
    pass

def write_salt():
    fi = open('.__META__.')
    salt = Random.get_random_bytes(AES.block_size)
    fi = open('.__META__.', 'w')
    fi.write(salt)

def get_salt():
    fi = open('.__META__.', 'rb')
    salt = fi.readline()
    fi.close()
    return salt

def write_encrypted_password(encrypted_password, username, url, nonce):
    return

def add_password():
    password = getpass.getpass('Master password: ')
    confirm_password = getpass.getpass('Confirm password: ')
    if password != confirm_password:
        print('Passwords do not match.\n')
        quit()
#    salt = get_salt()
    salt = Random.get_random_bytes(16)
    key = PBKDF2(password, salt, 32, count = 5000)
    password = ''
    confirm_password = ''
    
    done = False

    while not done:
        username = input("Enter the url where this password will be used: ")
        url = input("Enter the user name associated with this password: ") 
        password = getpass.getpass("Enter the account password: ")

        mapped_password = map_password(password)
        
        nonce = Random.get_random_bytes(AES.block_size/2)
        counter = Counter.new(4*AES.block_size, prefix = nonce, initial_value = 0)
        cipher = AES.new(key, AES.MODE_CTR, counter=counter)

        encrypted_password = cipher.encrypt(mapped_password)
        write_encrypted_password(encrypted_password, username, url, nonce)
        
        choice = input("Add another password? (Y/N) ")
        if choice.lower() != "y":
            done = True
        
    return

def add_random_password():
    password = getpass.getpass('Master password: ')
    confirm_password = getpass.getpass('Confirm password: ')
    if password != confirm_password:
        print('Passwords do not match.\n')
        quit()
    salt = get_salt()
    key = PBKDF2(password, salt, 32, count = 5000)
    password = ''
    confirm_password = ''

    done = False

    while not done:
        username = input("Enter the url where this password will be used: ")
        url = input("Enter the user name associated with this password: ") 
        # randomly generate password
        password = 'placeholder'

        mapped_password = map_password(password)
        
        nonce = Random.get_random_bytes(AES.block_size/2)
        counter = Counter.new(4*AES.block_size, prefix = nonce, initial_value = 0)
        cipher = AES.new(key, AES.MODE_CTR, counter=counter)

        encrypted_password = cipher.encrypt(mapped_password)
        write_encrypted_password(encrypted_password, username, url, nonce)
        
        choice = input("Add another password? (Y/N) ")
        if choice.lower() != "y":
            done = True

    return

def retrieve_enc_stuff(account):
    #parse password file to find password, iv
    #to_return = enc_password + enc_iv
    return

def decrypt_password(enc_stuff):
    #if we just want to pass both as one param:
    enc_password = enc_stuff[:-32]
    enc_iv = enc_stuff[-32:]
    salt = get_salt()
    #get master password
    #derive key from pasword
    #pwdkey = PBKDF2(password, salt, 32, count=1000)
    #remove password from memory
    #ecb_cipher = AES.new(key, AES.MODE_ECB)
    #iv = ecb_cipher.decrypt(enc_iv)
    #cbc_cipher = AES.new(key, AES.MODE_CBC, iv)
    #remove key from memory
    #padded_password = cbc_cipher.decrypt(enc_passowrd)
    #password = unpad(padded_password, AES.block_size)
    #copy password to clipboard(??)
    return

def delete_password():
    return

def print_help():
    print('Python Password Manager Help Dialog\n')
    print('add - [domain] add new username/domain and password combination')
    print('delete [domain] - remove a username/domain and password combination')
    print('help - print this help')
    print('quit - exit this program')
    print('retrieve [domain] - retrieve password associated with domain')
    print('')

if __name__ == '__main__':
    main()
