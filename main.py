__author__ = "Ari Conati, Gabriel Pinkard, and Lindsay Coffee-Johnson"
__licence__ = "MIT"

"""
ENCRYPTED PASSWORD ENTRY FORMAT:
URL
username/id
password
iv
"""

import os.path
import getpass
import sys
import pyperclip
from Crypto.Random import get_random_bytes
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
        get_cmd()


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
    # return key

def begin_session():
    print('Welcome. Please enter your master password.')
    password = getpass.getpass('Master password: ')
    confirm_password = getpass.getpass('Confirm password: ')
    if password != confirm_password:
        print('Passwords do not match.\n')
        quit()
    # derive key, return key


def get_cmd():
    print('Select an operation (add / delete / help / quit / retrieve)')
    cmd = input('> ').lower()
    if cmd == 'add':
        add_account()
    elif cmd == 'delete':
        delete_password()
    elif cmd == 'help':
        print_help()
    elif cmd == 'quit':
        print('Goodbye.')
        quit()
    elif cmd == 'retrieve':
        retrieve_password()
    else:
        print(cmd + ' is not a recognized command. Try \'help\'.')

# to implement

def is_first_session():
    if os.path.exists('.__META__.'):
        return False
    return True


def write_salt():
    fi = file.open('.__META__.')
    salt = Random.get_random_bytes(AES.block_size)
    fi = file.open('.__META__.', 'w')
    fi.write(salt)


def get_salt():
    fi = file.open('.__META__.', 'rb')
    salt = fi.readline()
    fi.close()
    return salt

#incorporated into add_account so no longer used:
def add_password_dialog():
    invalid_resp = True
    while(invalid_resp):
        print('Type "add" to add a password')
        print('Type "rand" to generate and add a random password (more secure)')
        print('Type cancel exit this dialog')
        resp = input('> ').lower()
        if resp == 'add':
            add_account()
            invalid_resp = False
        elif resp == 'rand':
            add_random_password()
            invalid_resp = False
        elif resp == 'cancel':
            invalid_resp = False


def add_account():
    invalid_resp = True
    url = ''
    account_id = ''
    enc_result = ''
    while(invalid_resp):
        print('What is the URL for the account you are adding?')
        resp = input('> ')
        url = resp
        print('Is ' + url + ' correct? (y/n)')
        resp = input('> ')
        if resp == 'y':
            invalid_resp = False
    
    invalid_resp = True
    while(invalid_resp):
        print('What is the username for the account you are adding?')
        resp = input('> ')
        account_id = resp
        print('Is ' + account_id + ' correct? (y/n)')
        resp = input('> ')
        if resp == 'y':
            invalid_resp = False
            
    invalid_resp = True
    while(invalid_resp):
        print('Would you like a password randomly generated for this account? (y/n)')
        resp = input('> ').lower()
        if resp == 'y':
            enc_result = enc_random_password()
            invalid_resp = False
        else:
            enc_result = enc_password()
            invalid_resp = False
    #enc_pass = enc_result[:-(size of nonce)]
    #enc_nonce = enc_result[-(size of nonce):]
    #write url, account_id, enc_pass, enc_nonce to password file


def enc_password():
    print('In add_password')
    #password = get from user
    #derive key from password
    #return enc_pass and enc_nonce
    return


def enc_random_password():
    print('In add_random_password')
    #if user doesn't supply a password:
    byte_password = Random.get_random_bytes(18)
    #password = Ari's function to map bytes to ASCII.(byte_password)
    #return enc_pass and enc_nonce
    return


"""
retrieves encryped password and iv as a tuple given a URL name
"""
def retrieve_encrypted_data(url):
    fi = open('.__PASS__.', 'r')
    data = fi.read('\n')
    fi.close()
    for i in range(0, len(data)):
        if data[i] == url:
            return (data[i+2], data[i+3])
    print('Error: ' + url + ' is not present in the password file')


def decrypt_password(enc_stuff):
    #if we just want to pass both as one param:
    enc_password = enc_stuff[:-32]
    enc_iv = enc_stuff[-32:]
    salt = get_salt()
    password = getpass.getpass('Master password: ')
    key = PBKDF2(password, salt, 32, count=5000)
    #remove password from memory
    ecb_cipher = AES.new(key, AES.MODE_ECB)
    iv = ecb_cipher.decrypt(enc_iv)
    cbc_cipher = AES.new(key, AES.MODE_CTR, iv)
    #remove key, iv from memory
    padded_password = cbc_cipher.decrypt(enc_passowrd)
    password = unpad(padded_password, AES.block_size)
    #copy password to clipboard
    pyperclip.copy(password)
    # may be unecessary, attempt to purge password from mem
    password = ''
    return

def delete_password_dialog():
    print('Type the domain of the password you wish to delete')
    domain = input('> ')
    exists = find_domain_ind(domain)
    if exists != -1:
        print('Are you sure you want to delete ' + domain + '[y/N]')
        resp = input('> ').toLower()
        if resp == 'y':
            delete_password()
    else:
        print(domain + ' was not found in the password file')


def find_domain_ind(domain):
    fi = file.open('.__PASS__.', 'r')
    data = fi.read()
    fi.close()
    for i in range(0, len(data)):
        if i % 4 == 0 and old_data[i] == account_url:
            return i
    return -1


"""
deletes the specified password (account_url) from the password file
"""
def delete_password(domain):
    fi = file.open('.__PASS__.', 'r')
    old_data = fi.read('\n')
    fi.close()
    new_data = ''
    """
    for i in range(0, len()):
        if i % 4 == 0 and old_data[i] == account_url:
            i += 3
        new_data = new_data + old_data[i]
    # erase contents of password file
    """
    ind = find_domain_ind(domain)
    new_data = data[0:ind] + data[ind+4:]
    open('.__PASS__.', 'w').close()
    fi = file.open('.__PASS__.', 'w')
    fi.write(new_data)
    fi.close()


def print_help():
    print('Python Password Manager Help Dialog\n')
    print('add - [domain] add new username/domain and password combination')
    print('delete [domain] - remove a username/domain and password combination')
    print('help - print this help')
    print('quit - exit this program')
    print('retrieve [domain] - retrieve password associated with domain\n')


if __name__ == '__main__':
    main()
