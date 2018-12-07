'''
Implements the mapping function described in mapping.md.
'''


import random

# The number of characters that can be used in account passwords
num_valid = 93

# The ASCII value of the lowest valid character
low_bound = 33

# The ASCII value of the highest valid character
high_bound = 126

# Number of ASCII characters
total_characters = 256

# The cutoff for triple vs double mappings with no shift
mapping_cutoff = 100

'''
Maps a given ASCII value to one of its possible mappings at
random. 
param letter_dec: The ASCII value of the character to be mapped. (integer)
param num_choices: Whether the given value is being mapped to 2 or 3 characters.
'''
def select_letter(letter_dec, num_choices):
    if num_choices != 2 and num_choices != 3:
        return ''
    choice = random.randint(1,num_choices)
    mapped_dec = 0
    if choice == 1:
       mapped_dec = letter_dec
    elif choice == 2:
        mapped_dec = letter_dec + num_valid + 1
    else:
        mapped_dec = letter_dec + 2*(num_valid+1)

    
    if mapped_dec > total_characters: 
        mapped_dec -= total_characters # wrap to valid ASCII range
        if mapped_dec >= low_bound: 
            mapped_dec += 2*(num_valid+1) 

    return chr(mapped_dec)


'''
Maps a given letter in accordance with the described mapping function.
param letter: The letter being mapped.
param shift: The shift/offset of the triple vs double mappings.
'''
def map_letter(letter, shift):
    letter_dec = ord(letter)
    if low_bound+shift <= letter_dec and letter_dec <= mapping_cutoff+shift:
        return select_letter(letter_dec, 3)
    else:
        return select_letter(letter_dec, 2)
        

'''
Maps a password containing only characters within the valid range
to a password containing any ASCII characters in accordance with the
mapping function outlined above.
param password: The password being mapped.
param shift: The shift/offset of the triple vs double mappings.
'''
def map_password(password, shift = -1):
    if shift > 26 or shift < 0:
        shift = random.randint(0,26)
    mapped_password = ''
    for letter in password:
        mapped_password += map_letter(letter, shift)
    if shift < 10:
        mapped_password += '0'
    mapped_password += str(shift)
    return mapped_password

'''
Remaps a mapped letter to its original value (for use after decryption).
param letter: The letter to be remapped.
param shift: The shift/offset of the triple vs double mappings used during the 
original mapping.
'''
def remap_letter(letter, shift):
    letter_dec = ord(letter)
    if letter_dec >= low_bound + 2*(num_valid + 1) and letter_dec < low_bound + 2*(num_valid+1) + shift: # 32 + 188 to 32 + 188 + shift
        letter_dec -= 4*(num_valid+1)
        letter_dec += total_characters # wrap to ASCII range
    if letter_dec < low_bound:
        letter_dec += total_characters
    while letter_dec > high_bound:
        letter_dec -= (num_valid+1)
    return chr(letter_dec)

'''
Remaps a mapped password to the original password (for use after decryption).
'''
def remap_password(mapped_password):
    password = ''
    shift = int(mapped_password[len(password) - 2:])
    mapped_password = mapped_password[0:len(password) - 2]
    for letter in mapped_password:
        password += remap_letter(letter, shift)
    return password


# Only for testing purposes
"""
for i in range(1000):
    password = ''
    for j in range(10):
        password += chr(random.randint(33, 126))

    shift = random.randint(0,26)
    mapped_password = map_password(password, shift)
    remapped_password = remap_password(mapped_password) 

    #print(password)
    #print(mapped_password)
    #print(remapped_password)
    if password != remapped_password:
        print(shift)
        print(password)
        print(mapped_password)
        print(remapped_password)
        quit()
        
        
    if i == 999:
        print('last')
        print(shift)
        print(password)
        print(mapped_password)
        print(remapped_password)
"""
