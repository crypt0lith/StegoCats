# author: @crypt0lith

import os
import sys
import argparse
import tempfile
import secrets
import string
from PIL import Image
from dependencies import arcfour
from dependencies.LSBSteg import *


class StegoCats:

    def validate_user_key(self, user_key):
        # Function to validate user-inputted keys
        # Check for any problematic characters that could lead to injection attacks
        problematic_characters = ['\\', '"', "'", ';', ':', '*', '&', '|', '`']
        if any(char in user_key for char in problematic_characters):
            print("Error: Invalid characters in the user key.")
            sys.exit(1)

    def generate_key(self, key_strength):
        # Function to generate keys with input sanitization and normalization
        safe_characters = string.ascii_letters + string.digits + '$@#%'
        key_length = 12  # Default key length
        key_strength_levels = {
            0: 6,  # 10th percentile (weak but still secure)
            1: 8,  # 20th percentile
            2: 10,  # 30th percentile
            3: 10,  # 40th percentile
            4: 12,  # 50th percentile (medium secure, default)
            5: 16,  # 60th percentile
            6: 20,  # 70th percentile
            7: 24,  # 80th percentile
            8: 32,  # 90th percentile
            9: 63  # 100th percentile (almost unbreakable, maximum-entropy)
        }

        if key_strength in key_strength_levels:
            key_length = key_strength_levels[key_strength]

        # Generate a key with sanitized characters
        generated_key = ''.join(secrets.choice(safe_characters) for _ in range(key_length))
        return generated_key

    def read_plaintext_file(self, input_file):
        with open(input_file) as f:
            return ' '.join(line.strip() for line in f)

    def encrypt_message(self, key, plaintext):
        s = arcfour.encrypt(key, plaintext)
        t = iter(s)
        return ' '.join(a + b for a, b in zip(t, t))

    def resize_image(self, input_image, max_size=1000000):
        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as temp_image:
            output_name = temp_image.name
            with Image.open(input_image) as image:
                aspect_ratio = image.width / image.height
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
                new_width = image.width
                new_height = image.height
                if aspect_ratio > closest_aspect_ratio:
                    new_width = int(new_height * closest_aspect_ratio)
                else:
                    new_height = int(new_width / closest_aspect_ratio)
                resized_image = image.resize((new_width, new_height))
                resized_image.save(output_name, format="PNG", optimize=True)
                output_size = os.path.getsize(output_name)
                if output_size > max_size:
                    ratio = max_size / output_size
                    new_width = int(new_width * ratio)
                    new_height = int(new_height * ratio)
                    resized_image = image.resize((new_width, new_height))
                    resized_image.save(output_name, format="PNG", optimize=True)
        return output_name

    def hide_message(self, input_image, key, data, output_file):
        steg = LSBSteg(cv2.imread(input_image))
        new_img = steg.encode_binary(data)
        cv2.imwrite(output_file, new_img)

    def read_key(self, key_file):
        with open(key_file, 'r') as f:
            key_hex = f.read().strip()
        try:
            key = bytes.fromhex(key_hex).decode('utf-8')
            return key
        except ValueError:
            print("Error: The key is not in a valid hexadecimal format.")
            sys.exit(1)

    def save_key_to_file(self, key, output_file):
        key_hex = key.encode('utf-8').hex()
        key_file_name = os.path.abspath(
            os.path.join("data", os.path.basename(output_file).replace('.png', '.key').replace('.jpg', '.key')))
        with open(key_file_name, 'w') as f:
            f.write(key_hex)
        print("Key saved as:", key_file_name)

    def decrypt_message(self, input_image, key):
        steg = LSBSteg(cv2.imread(input_image))
        binary = steg.decode_binary()
        ciphertext = str(binary).replace('b', '').replace("'", '').replace(' ', '')
        try:
            decrypted_message = arcfour.decrypt(str(key), ciphertext)
            return decrypted_message
        except UnicodeDecodeError:
            print("Error: Invalid key.")
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="StegoCats - Image Steganography Tool")
    parser.add_argument("-a", "--action", choices=["encode", "decode"], required=True,
                        help="Specify the action to perform: encode or decode")
    parser.add_argument("-i", "--input-image", required=True, metavar="<input_image>",
                        help="Path to the input image")
    parser.add_argument("-f", "--input-file", metavar="<input_file>",
                        help="Path to the input text file for encoding")
    parser.add_argument("-o", "--output-file", metavar="<output_file>",
                        help="Path to the output image file for encoding/decoding")
    parser.add_argument("-k", "--key", metavar="<key>",
                        help="Use a custom key for encoding/decoding. Cannot be used with -kS.")
    parser.add_argument("-kF", "--key-file", metavar="<key_file>",
                        help="Path to the key file for decoding")
    parser.add_argument("-kS", "--key-strength", type=int, choices=range(10), default=4,
                        help="Specify the strength level of the generated key (0-9). Default: 4.")

    args = parser.parse_args()

    stegocats = StegoCats()

    # Validate and sanitize the user-provided key if available
    if args.key:
        stegocats.validate_user_key(args.key)

    # Generate a key only if not using custom key
    if not args.key:
        generated_key = stegocats.generate_key(args.key_strength)

    if args.action == "encode":

        # Set default output directory and filename if not provided
        if not args.output_file:
            input_filename = os.path.splitext(os.path.basename(args.input_image))[0]
            args.output_file = os.path.join("output", input_filename + "_encoded.png")

        # Check if a custom key was provided
        if args.key:
            key = str(args.key)
            if len(key) < 6:
                print("Error: The custom key must be at least 6 characters long.")
                sys.exit(1)
            else:
                stegocats.save_key_to_file(key, args.output_file)
                print("Key:", key)
        else:
            # Use the generated key and write it to the key file if output file is provided
            key = generated_key
            if args.output_file:
                stegocats.save_key_to_file(key, args.output_file)
                print("Key:", key)

        # Read the plaintext file
        plaintext = stegocats.read_plaintext_file(args.input_file)

        # Encrypt the message
        ciphertext = stegocats.encrypt_message(key, plaintext)
        binary = ciphertext.encode('ascii')

        with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as temp_data:
            with open(temp_data.name, 'wb') as f:
                f.write(binary)

            # Resize the image
            resized_image_name = stegocats.resize_image(args.input_image, max_size=100000)

            # Hide the encrypted message in the binary data of the image
            data = open(temp_data.name, "rb").read()
            stegocats.hide_message(resized_image_name, key, data, args.output_file)

        print('Image saved as ' + os.path.abspath(args.output_file))


    elif args.action == "decode":

        if args.key:

            key = args.key

            if len(key) < 6:
                print("Error: The custom key must be at least 6 characters long.")

                sys.exit(1)


        else:

            # Check if a key file is provided

            if args.key_file:

                key_file_path = os.path.abspath(args.key_file)

                if not os.path.isfile(key_file_path):
                    print("Error: The specified key file does not exist.")

                    sys.exit(1)

                # Read the key from the provided key file

                key = stegocats.read_key(key_file_path)


            else:

                print("Error: No key provided for decryption.")

                sys.exit(1)

        # Decrypt the message

        decrypted_message = stegocats.decrypt_message(args.input_image, key)

        print(decrypted_message)


if __name__ == "__main__":
    main()
