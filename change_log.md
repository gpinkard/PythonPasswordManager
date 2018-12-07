#Logs implementation details that have changed from the initial design 
document to address potential weaknesses.

..*The hashed key derived from the master password is no longer stored. While
   the user is no longer informed that they have entered their master password
   incorrectly, neither is the attacker. Even if an incorrect password is 
   supplied a key will be derived and used to decrypt account passwords as
   requested.

..*Encryption of account passwords now uses CTR mode over CBC mode. While this
   no longer obscures the length of the account password, attackers no longer
   have a way of verifying whether an account password was decrypted correctly
   via the app. When CBC mode was used, the attacker could have potentially 
   used a padding oracle type attack where they could verify if an account
   password was decrypted correctly based on whether the padding was 
   correct.

..*Even with the above changes, the attacker still would have had a way to 
   verify whether account passwords were decrypted correctly. This is 
   because account passwords exclusively use alphabetical, numeric, and
   some symbol characters. Therefore, if an account password was
   decrypted with the wrong key and contained invalid characters (very
   likely), the attacker would know that the key was incorrect. This problem
   has been remedied through the addition of a mapping function which maps
   a password containing only valid characters to the entire ASCII range.
   Therefore an attacker has no way of knowing whether an account password
   was decrypted properly or not. The more specific implementation details
   of the mapping function are found in mapping.md.
