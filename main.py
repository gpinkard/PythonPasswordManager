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
    print("""
    Welcome to the Python Password Manager. Since this is your
    first time using this program, think of a \'master\' password.
    This password will be used any time you want to add, delete,
    or retrieve a passsword for a site. This password is never
    stored, so it is up to you to remember it and type it in
    correctly. Make a strong password, with at least ten
    characters, and do not use obvious personal facts (name,
    birthdays, sportsteams), or weak passwords (p@ssword, 1234five
    asdfasdfasdf, etc.). 

    Please also make sure that you have pycryptodome and pyperclip
    for python3 installed on your machine.
    """)
    x = input('Press any key to continue.')
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
        retrieve_password_dialog()
    else:
        print(cmd + ' is not a recognized command. Try \'help\'.')


"""
Returns true if this is the first session ever.
"""
def is_first_session():
    if os.path.exists('.__META__.'):
        return False
    return True

"""
Generates and writes salt to file.
"""
def write_salt():
    p_fi = open('.__PASS__.', 'w')
    p_fi.close()
    salt = Random.get_random_bytes(8)
    fi = open('.__META__.', 'wb')
    fi.write(salt)
    fi.close()


"""
Returns salt from file.
"""
def get_salt():
    fi = open('.__META__.', 'rb')
    salt = fi.read()
    fi.close()
    return salt


"""
Adds account to password file.
"""
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


"""
Asks user if they would like to generate a random password instead of using one of their own.
"""
def query_random_pass():
    enc_result = ''
    while(True):
        print('Would you like a password randomly generated for this account (generally more secure)? [y/n]')
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

"""
Asks the user for the username of the account they are creating.
"""
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


"""
Asks user for URL when adding a new account.
"""
def query_url():
    while(True):
        print('What is the URL for the account you are adding?')
        resp = input('> ')
        url = resp
        print('Is ' + url + ' correct? [y/N]')
        resp = input('> ')
        if resp == 'y':
            return url


"""
Query user for password, then encrypt it. Returns encrypted password and encrypted nonce
"""
def enc_password():
    password = getpass.getpass("Enter the account password: ")

    master_pass = 'password' 
    confirm_password = 'confirm'
    while master_pass != confirm_password:
        master_pass = getpass.getpass('Enter master password: ')
        confirm_password = getpass.getpass('Confirm password: ')
        if master_pass != confirm_password:
            print('Passwords do not match.\n')
        else:
            break

    salt = get_salt()
    key = PBKDF2(master_pass, salt, 32, count = 100000)
    master_pass = ''
    confirm_password = ''

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

"""
Generates a random password for the user
"""
def enc_random_password():
    master_pass = 'password' 
    confirm_password = 'confirm'
    while master_pass != confirm_password:
        master_pass = getpass.getpass('Enter master password: ')
        confirm_password = getpass.getpass('Confirm password: ')
        if master_pass != confirm_password:
            print('Passwords do not match.\n')
        else:
            break

    salt = get_salt()
    key = PBKDF2(master_pass, salt, 32, count = 100000)
    master_pass = ''
    confirm_password = ''

    password_length = 16
    password = ''

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


"""
Query user for retrieving password
"""
def retrieve_password_dialog():
    enc_data = ''
    while(True):
        print('type \'url\' to retrieve by URL, or \'username\' to retrieve by username')
        resp = input('> ')
        if resp == 'url':
            print('enter the url (ex: www.google.com)')
            resp = input('> ')
            pwd = retrieve_encrypted_data_url(resp)
            if pwd != None:
                decrypt_password(pwd)
            else:
                print(resp + ' is not a valid url')
            break
        elif resp == 'username':
            print('enter the username (ex: jsmith)')
            resp = input('> ')
            pwd = retrieve_encrypted_data_username(resp)
            if pwd != None:
                decrypt_password(pwd)
            else:
                print(resp + ' is not a valid username')
            break
    print('password copied to clipboard')


"""
retrieves encryped password and iv as a tuple given a URL name
"""
def retrieve_encrypted_data_url(url):
    fi = open('.__PASS__.', 'rb')
    data = fi.readlines()
    fi.close()
    for i in range(0, len(data), 5):
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
            clean = clean_return_val(data[i-1].decode('utf-8'))
            accounts[clean] = i-1
    if len(accounts) > 1:
        print('There are several accounts associated with the username ' + username)
        print('Type in the number associated with the account for retreival')
        tmp = {}
        ctr = 1
        for acc in accounts.items():
            # DON'T REMOVE THIS PRINT STATEMENT
            print(str(ctr) + ': ' + str(acc[0]))
            tmp[ctr] = acc[1]
            ctr += 1
        while(True):
            ind = input('> ')
            try:
                ind = int(ind)
            except Exception:
                print('input must be a valid number')
                continue
            if ind > 0 and ind < len(accounts) + 1:
                ind_account = tmp[ind]
                return (data[ind_account+2], data[ind_account+3])
            else:
                print(str(ind) + ' is not a valid index for retrieval')
    elif len(accounts) == 1:
        ind = list(accounts.values())[0]
        return (data[ind+2], data[ind+3])
    else:
        print('The username ' + username + ' is not associated with any accounts')

"""
decrypts password
"""
def decrypt_password(enc_stuff):
    enc_password = enc_stuff[0]
    enc_password = enc_password[0:len(enc_password) - 1]
    enc_nonce = enc_stuff[1]
    enc_nonce = enc_nonce[0:len(enc_nonce) - 1]

    salt = get_salt()
    password = getpass.getpass('Enter your master password: ')
    key = PBKDF2(password, salt, 32, count=100000)
    ecb_cipher = AES.new(key, AES.MODE_ECB)
    nonce = ecb_cipher.decrypt(enc_nonce)[0:int(AES.block_size/2)]
    cntr = Counter.new(64, prefix=nonce, initial_value=0)
    ctr_cipher = AES.new(key, AES.MODE_CTR, counter=cntr)
    key = ''
    nonce = ''
    password = ctr_cipher.decrypt(enc_password)
    try:
        password = password.decode('utf-8')
    except Exception:
        password = ''
    if password != '':
        password = remap_password(password)

    pyperclip.copy(password)
    password = ''
    return

"""
Dialog for when a user wants to delete a password
"""
def delete_password_dialog():
    while(True):
        print('Enter the \'url\' of the account you would like to delete (\'c\' to cancel)')
        resp = input('> ').lower()
        if resp == 'c':
            return
        else:
            url = resp
            print('Are you sure you want to delete ' + url + '? [y/N]')
            resp = input('> ').lower()
            if resp == 'y':
                ind = get_ind_url(url)
                if ind != -1:
                    delete_password(url, ind)
                    break
                else:
                    print(resp + ' is not a valid url')


"""
deletes the specified password (account_url) from the password file
"""
def delete_password(domain, ind):
    fi = open('.__PASS__.', 'rb')
    old_data = fi.readlines()
    fi.close()
    new_data = ''
    if ind == 0:
        new_data = old_data[5:]
    else:
        new_data = old_data[0:ind] + old_data[ind+5:]
    fi = open('.__PASS__.', 'wb')
    for l in new_data:
        fi.write(l)
    fi.close()
    print('successfully deleted ' + domain)


"""
gets the index in the password file for a given url
"""
def get_ind_url(url):
    fi = open('.__PASS__.', 'rb')
    data = fi.readlines()
    fi.close()
    for i in range(0, len(data), 5):
        if data[i].decode('utf-8').strip('\n') == 'URL:' + url:
            return i
    return -1


"""
gets the index for a username in the password file given a username
"""
def get_ind_username(username):
    fi = open('.__PASS__.', 'rb')
    data = fi.readlines()
    fi.close()
    for i in range(1, len(data), 5):
        if data[i].decode('utf-8').strip('\n') == 'USERNAME:' + username:
            return (i - 1) 
    return -1


def print_help():
    print("""
    Python Password Manager Help Dialog\n
    add - add new username/domain and password combination.
    delete - remove a username/domain and password combination
    help - print this help
    quit - exit this program
    retrieve - retrieve password associated with a specified domain\n
    """)


if __name__ == '__main__':
        main()
