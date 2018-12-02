"""
Things to do:
1. check if there is a meta file (of the form '#META#')
"""
import os.path
import getpass
import sys

from Crypto.Cipher import AES
from Crypto.Util import Padding

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
    # authenticate password (maybe ??)
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
    elif cmd == 'retrive':
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

def write_salt(salt):
    fi = file.open('.__META__.')
    data = fi.read('\n')
    data[0] = salt
    fi.write(data)
    fi.close()

def add_password(key):
    return

def retrieve_enc_stuff(account):
    #parse password file to find password, iv
    #to_return = enc_password + enc_iv
    return

def decrypt_password(enc_stuff):
    #if we just want to pass both as one param:
    enc_password = enc_stuff[:-32]
    enc_iv = enc_stuff[-32:]
    #get master password
    #derive key from pasword
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
