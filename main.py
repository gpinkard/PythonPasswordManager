"""
Things to do:
1. check if there is a meta file (of the form '#META#')
"""
import os.path
import getpass

def firstSession():
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
        

def beginSession():
    print('Welcome. Please enter your master password.')
    password = getpass.getpass('Master password: ')
    confirm_password = 'confirm'
    confirm_password = getpass.getpass('Confirm password: ')
    if password != confirm_password:
        print('Passwords do not match.\n')
        quit()
    # authenticate password (maybe ??)
    # derive key, return key

def getOperation():
    return input('Select an operation (add / retrieve / delete / help / quit): ').lower()

# to implement

def isFirstSession():
    return True

def deriveKey(password, salt):
    return

def writeKeyHash(keyHash):
    return

def writeSalt(salt):
    return

def addPassword(key):
    return

def retrievePassword(key):
    return

def deletePassword():
    return


def main():
    print('python password manager')
    key = ''
    if isFirstSession():
        key = firstSession()
    else:
        key = beginSession()

if __name__ == "__main__":
    main()

