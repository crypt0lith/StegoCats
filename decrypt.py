import arcfour
from LSBSteg import *

steg = LSBSteg(cv2.imread("output/funnycat_434c69574450504a.png"))
binary = steg.decode_binary()
ciphertext = str(binary).replace('b', '').replace("'", '').replace(' ', '')

# Read key from text file
with open('data/key.txt', 'r') as f:
    key = f.read()

decrypted_message = arcfour.decrypt(key, ciphertext)
print(decrypted_message)
