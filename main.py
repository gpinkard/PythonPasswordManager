"""
Things to do:
1. check if there is a meta file (of the form '#META#')
"""
import os.path
import getpass
import sys

def main():
    print('\n=== Python Password Manager ===\n')
    key = ''
    if isFirstSession():
        key = firstSession()
    else:
        key = beginSession()
    printHelp()
    while(True):
        getOperation()

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
    # ask for password twice so we don't have to save hash
    confirm_password = 'confirm'
    confirm_password = getpass.getpass('Confirm password: ')
    if password != confirm_password:
        print('Passwords do not match.\n')
        quit()
    # authenticate password (maybe ??)
    # derive key, return key

def getOperation():
    cmd = input('Select an operation (add / delete / help / quit / retrieve): ').lower()
    if cmd == 'add':
        addPassword()
    elif cmd == 'delete':
        deletePassword()
    elif cmd == 'help':
        printHelp()
    elif cmd == 'quit':
        print('Goodbye')
        sys.exit(0)
    elif cmd == 'retrive':
        retrievePassword()
    else:
        print(cmd + ' is not a recognized command. Try \'help\'')

# to implement

def isFirstSession():
    if os.path.exists('.__META__.'):
        return False
    return True

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

def printHelp():
    print('Possible Operatons\n')
    print('add - [domain] add new username/domain and password combination')
    print('delete [domain] - remove a username/domain and password combination')
    print('help - print this help')
    print('quit - exit this program')
    print('retrieve [domain] - retrieve password associated with domain')
    print('')

if __name__ == '__main__':
    main()
