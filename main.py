__author__ = "Ari Conati, Gabriel Pinkard, and Lindsey Coffee-Johnson"
__licence__ = "MIT"

"""
ENCRYPTED PASSWORD ENTRY FORMAT:
URL
username/id
password
nonce
"""

import os.path
import getpass
import sys
import pyperclip
from Crypto.Random import get_random_bytes
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util import Padding
from Crypto.Util import Counter
from mapping import *


def main():
    print('\n=== Python Password Manager ===\n')
    key = ''
    if is_first_session():
        first_session()
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
    write_salt()


def get_cmd():
    print('Select an operation (add / delete / help / quit / retrieve)')
    cmd = input('> ').lower()
    if cmd == 'add':
        add_account()
    elif cmd == 'delete':
        delete_password_dialog()
    elif cmd == 'help':
        print_help()
    elif cmd == 'quit':
        print('Goodbye.')
        quit()
    elif cmd == 'retrieve':
        # retrieve_password()
        retrieve_password_dialog()
    else:
        print(cmd + ' is not a recognized command. Try \'help\'.')


def is_first_session():
    if os.path.exists('.__META__.'):
        return False
    return True


def write_salt():
    p_fi = open('.__PASS__.', 'w')
    p_fi.close()

    salt = Random.get_random_bytes(8)
    fi = open('.__META__.', 'wb')
    fi.write(salt)
    fi.close()


def get_salt():
    fi = open('.__META__.', 'rb')
    salt = fi.read()
    fi.close()
    return salt


def add_account():
    url = 'URL:' + query_url() + '\n'
    url = url.encode('utf-8')
    account_id = 'USERNAME:' + query_account_id() + '\n'
    account_id = account_id.encode('utf-8')
    enc_result = query_random_pass() 
    enc_pass = enc_result[0]
    enc_nonce = enc_result[1]
    
    pass_file = open('.__PASS__.', 'rb')
    fi_contents = pass_file.read()
    pass_file.close()

    encoded_new_line = '\n'.encode('utf-8')

    fi_contents +=  url + account_id + enc_pass + encoded_new_line + enc_nonce + encoded_new_line + encoded_new_line

    pass_file = open('.__PASS__.', 'wb')
    pass_file.write(fi_contents)
    pass_file.close()

    print('Account successfully added.\n')

    
def query_random_pass():
    enc_result = ''
    while(True):
        print('Would you like a password randomly generated for this account? [y/n]')
        resp = input('> ').lower()
        if resp == 'y':
            enc_result = enc_random_password()
            break
        elif resp == 'n':
            enc_result = enc_password()
            break
        else:
            print('an explicit y or n is required')
    return enc_result
  
def query_account_id():
    while(True):
        print('What is the username for the account you are adding?')
        resp = input('> ')
        account_id = resp
        # this is a test
        print('Is ' + account_id + ' correct? [y/N]')
        resp = input('> ')
        if resp == 'y':
            return account_id
    

def query_url():
    while(True):
        print('What is the URL for the account you are adding?')
        resp = input('> ')
        url = resp
        print('Is ' + url + ' correct? [y/N]')
        resp = input('> ')
        if resp == 'y':
            return url


def enc_password():
    #derive key from password
    password = getpass.getpass('Master password: ')
    confirm_password = getpass.getpass('Confirm password: ')
    if password != confirm_password:
        print('Passwords do not match.\n')
        quit()
    salt = get_salt()
    key = PBKDF2(password, salt, 32, count = 100000)
    password = ''
    confirm_password = ''

    password = getpass.getpass("Enter the account password: ")
    mapped_password = map_password(password)
    
    nonce = Random.get_random_bytes(int(AES.block_size/2))
    padded_nonce = nonce
    for x in range(int(AES.block_size/2)):
        padded_nonce += b'\x00'
        
    counter = Counter.new(4*AES.block_size, prefix = nonce, initial_value = 0)
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)

    ecb_cipher = AES.new(key, AES.MODE_ECB)
    encrypted_nonce = ecb_cipher.encrypt(padded_nonce)

    encrypted_password = cipher.encrypt(mapped_password.encode('utf-8'))
    return (encrypted_password, encrypted_nonce)

def enc_random_password():
    #if user doesn't supply a password:
    
    password = getpass.getpass('Enter your master password: ')
    confirm_password = getpass.getpass('Confirm password: ')
    salt = get_salt()
    key = PBKDF2(password, salt, 32, count = 100000)
    password = ''
    confirm_password = ''
    
    password_length = 16

    for x in range(password_length):
        random_ascii_value = random.randint(33,126)
        password += chr(random_ascii_value)


    mapped_password = map_password(password)
    
    nonce = Random.get_random_bytes(int(AES.block_size/2))
    padded_nonce = nonce
    for x in range(int(AES.block_size/2)):
        padded_nonce += b'\x00'

    counter = Counter.new(4*AES.block_size, prefix = nonce, initial_value = 0)
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)

    ecb_cipher = AES.new(key, AES.MODE_ECB)
    encrypted_nonce = ecb_cipher.encrypt(padded_nonce)

    encrypted_password = cipher.encrypt(mapped_password.encode('utf-8'))
    return (encrypted_password, encrypted_nonce)


def retrieve_password_dialog():
    enc_data = ''
    while(True):
        print('type \'url\' to retrieve by URL, or \'username\' to retrieve by username')
        resp = input('> ')
        if resp == 'url':
            print('enter the url (ex: www.google.com)')
            resp = input('> ')
            enc_data = retrieve_encrypted_data_url(resp)
            break 
        elif resp == 'username':
            print('enter the username (ex: jsmith)')
            resp = input('> ')
            enc_data = retrieve_encrypted_data_username(resp)
            break

    decrypt_password(enc_data)
            

"""
retrieves encryped password and iv as a tuple given a URL name
"""
def retrieve_encrypted_data_url(url):
    fi = open('.__PASS__.', 'rb')
    data = fi.readlines()
    fi.close()
    for i in range(0, len(data), 5):
        print(data[i].decode('utf-8'))
        if data[i].decode('utf-8').strip('\n') == 'URL:' + url:
            # return (data[i+2], data[i+3])
            pwd = data[i+2]
            nonce = data[i+3]
            return (pwd, nonce) 
    print('Error: ' + url + ' is not present in the password file')


"""
removes URL, PASSWORD etc. tags from input. Expects non-encoded text
"""
def clean_return_val(data):
    tmp = data.split(':')
    clean_str = ''
    for sub in tmp[1:]:
        clean_str += sub
    return clean_str


"""
retrieve encrypted data, but with a username.
BIG AND UGLY :o
"""
def retrieve_encrypted_data_username(username):
    fi = open('.__PASS__.', 'rb')
    data = fi.readlines()
    fi.close()
    accounts = {}
    for i in range(1, len(data), 5):
        data[i] = str(data[i].decode('utf-8').strip('\n'))
        # data[i] = data[i].strip()
        if data[i] == "USERNAME:" + username:
            # accounts.append(data[i-1]) # url is before username
            clean = clean_return_val(data[i-1])
            accounts[clean] = i-1
    if len(accounts) > 1:
        print('There are several accounts associated with the username ' + username)
        print('Type in the number associated with the account for retreival')
        tmp = {}
        ctr = 1
        for acc in accounts.items():
            print(str(ctr) + ': ' + str(acc))
            tmp[ctr] = acc[1]
            ctr += 1
        while(True):
            ind = int(input('> '))
            if ind > 0 and ind < len(accounts) + 1:
                ind_account = tmp[ind]
                print(data[ind_account+2], data[ind_account+3])
                return (data[ind_account+2], data[ind_account+3])
            else:
                print(str(ind) + ' is not a valid index for retrieval')
    elif len(accounts) == 1:
        ind = list(accounts.values())[0]
        print((data[ind+2], data[ind+3]))
        return (data[ind+2], data[ind+3])
    else:
        print('The username ' + username + ' is not associated with any accounts')

def decrypt_password(enc_stuff):
    #if we just want to pass both as one param:
    enc_password = enc_stuff[0]
    enc_nonce = enc_stuff[1]
    enc_password = enc_password[:-1]
    enc_nonce = enc_nonce[:-1]
    print(enc_nonce)
    salt = get_salt()
    password = getpass.getpass('Enter your master password: ')
    key = PBKDF2(password, salt, 32, count=100000)
    #remove password from memory
    ecb_cipher = AES.new(key, AES.MODE_ECB)
    nonce = ecb_cipher.decrypt(enc_nonce)[0:int(AES.block_size/2)]
    # intialize a counter with the nonce as prefix and initial counter value 0
    cntr = Counter.new(64, prefix=nonce, initial_value=0)
    ctr_cipher = AES.new(key, AES.MODE_CTR, counter=cntr)
    key = ''
    nonce = ''
    #remove key, nonce from memory
    password = ctr_cipher.decrypt(enc_password).decode('utf-8')
    password = remap_password(password)
    #copy password to clipboard
    pyperclip.copy(password)
    print(password)
    password = ''
    return

def delete_password_dialog():
    print('Type the domain of the password you wish to delete')
    domain = input('> ')
    exists = find_domain_ind(domain)
    if exists != -1:
        print('Are you sure you want to delete ' + domain + '[y/n]')
        resp = input('> ').toLower()
        if resp == 'y':
            delete_password()
    else:
        print(domain + ' was not found in the password file')

        
"""
deletes the specified password (account_url) from the password file
"""
def delete_password(domain):
    fi = file.open('.__PASS__.', 'rb')
    old_data = fi.readlines()
    fi.close()
    new_data = ''
    ind = 0
    for i in range(0, len(old_data)):
        if old_data[i].decode('utf-8').strip() == 'URL:' + domain:
            i += 3
        if i < len(old_data):
            new_data.append(data[i])
    open('.__PASS__.', 'wb').close()
    fi = file.open('.__PASS__.', 'wb')
    fi.write(new_data)
    fi.close()


def print_help():
    print("""
    Python Password Manager Help Dialog\n
    add - [domain] add new username/domain and password combination
    delete [domain] - remove a username/domain and password combination
    help - print this help
    quit - exit this program
    retrieve [domain] - retrieve password associated with domain\n
    """)


if __name__ == '__main__':
    main()
