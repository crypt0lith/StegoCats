import os
import secrets
import string

from PIL import Image

import arcfour
from LSBSteg import *


def generate_key():
    return ''.join(secrets.choice(string.ascii_letters) for i in range(8))


# Generate key and save as text file
key: str = generate_key()
with open('data/key.txt', 'w') as f:
    f.write(key)
print("key:", key)

hex_key = key.encode('utf-8').hex()

# Read the plaintext file
with open('data/plain.txt') as f:
    plaintext = ' '.join(line.strip() for line in f)
    print('plaintext:', plaintext)

# Encrypt the message
s = arcfour.encrypt(key, plaintext)
t = iter(s)
ciphertext = ' '.join(a + b for a, b in zip(t, t))
binary = ciphertext.encode('ascii')
with open('data/data.bin', 'wb') as f:
    f.write(binary)
print("ciphertext:", ciphertext)

image_name = 'images/funnycat.jpg'
output_name = image_name.replace('.png', '_scaled.png').replace('.jpg', '_scaled.png')


def resize_image(input_path, output_path, max_size=1000000):
    # Open the image using PIL
    with Image.open(input_path) as image:
        # Get the original aspect ratio
        aspect_ratio = image.width / image.height

        # Determine the closest aspect ratio to use for resizing
        aspect_ratios = {
            1 / 1: (1, 1),
            9 / 16: (9, 16),
            16 / 9: (16, 9),
            4 / 5: (4, 5),
            5 / 4: (5, 4),
            5 / 7: (5, 7),
            7 / 5: (7, 5)
        }
        closest_aspect_ratio = min(aspect_ratios, key=lambda x: abs(x - aspect_ratio))
        target_aspect_ratio = aspect_ratios[closest_aspect_ratio]

        # Calculate the new size for the image
        new_width = image.width
        new_height = image.height
        if aspect_ratio > closest_aspect_ratio:
            new_width = int(new_height * closest_aspect_ratio)
        else:
            new_height = int(new_width / closest_aspect_ratio)

        # Resize the image
        resized_image = image.resize((new_width, new_height))

        # Save the resized image
        resized_image.save(output_path, format="PNG", optimize=True)

        # Check the size of the output image and resize if necessary
        output_size = os.path.getsize(output_path)
        if output_size > max_size:
            ratio = max_size / output_size
            new_width = int(new_width * ratio)
            new_height = int(new_height * ratio)
            resized_image = image.resize((new_width, new_height))
            resized_image.save(output_path, format="PNG", optimize=True)


resize_image(image_name, output_name, max_size=400000)

# Hide encrypted message in binary data of the image
steg = LSBSteg(cv2.imread(output_name))
data = open("data/data.bin", "rb").read()
new_img = steg.encode_binary(data)

# Output file saved as file name and key in hex
file_name = output_name.replace('images/', 'output/').replace('scaled', hex_key)
cv2.imwrite(file_name, new_img)
print('Image saved as ' + file_name.strip('output/'))
