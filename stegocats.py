import os
import sys
import argparse
import tempfile
import secrets
import string
from PIL import Image
from dependencies import binary_arcfour
from dependencies.LSBSteg import *


class StegoCats:

    def __init__(self, verbose=False, debug=False):
        self.verbose = verbose
        self.debug = debug
        self.temp_files = []
        self.temp_dir = tempfile.mkdtemp(prefix='stegocats_')

    def print_message(self, message, is_debug=False):
        if self.debug or (self.verbose and not is_debug):
            print(message)

    def validate_user_key(self, user_key):
        problematic_characters = ['\\', '"', "'", ';', ':', '*', '&', '|', '`']
        if any(char in user_key for char in problematic_characters):
            print("Error: Invalid characters in the user key.")
            sys.exit(1)

    def generate_key(self, key_strength):
        safe_characters = string.ascii_letters + string.digits + '$@#%'
        key_length = 12
        key_strength_levels = {
            0: 6,
            1: 8,
            2: 10,
            3: 10,
            4: 12,
            5: 16,
            6: 20,
            7: 24,
            8: 32,
            9: 63
        }

        if key_strength in key_strength_levels:
            key_length = key_strength_levels[key_strength]

        generated_key = ''.join(secrets.choice(safe_characters) for _ in range(key_length))
        return generated_key

    def read_plaintext_file(self, input_file):
        with open(input_file) as f:
            return ' '.join(line.strip() for line in f)

    def encrypt_binary_arcfour(self, key_bytes, data):
        salt = os.urandom(16)
        ciphertext = binary_arcfour.encrypt(key_bytes, salt, data)
        return salt + ciphertext

    def encrypt_message(self, key, plaintext_data):
        key_bytes = key.encode('utf-8')
        plaintext_bytes = plaintext_data
        self.print_message(f"Plaintext: {plaintext_bytes}")
        self.print_message(f"Cipher key: {key_bytes}", is_debug=True)
        self.print_message(f"Hash of the key: {hash(key_bytes)}", is_debug=True)
        ciphertext_bytes = self.encrypt_binary_arcfour(key_bytes, plaintext_bytes)
        self.print_message(f"Ciphertext: {ciphertext_bytes}")
        return ciphertext_bytes

    def resize_image(self, input_image, max_size=1000000):
        with tempfile.NamedTemporaryFile(suffix='.png', dir=self.temp_dir, delete=False) as temp_image:
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
        self.temp_files.append(output_name)
        return output_name

    def hide_message(self, input_image, key, data, output_file):
        self.print_message("Hiding message in the image")
        self.print_message(f"Input image: {input_image}", is_debug=True)
        self.print_message(f"Output image: {output_file}", is_debug=True)
        steg = LSBSteg(cv2.imread(input_image))
        new_img = steg.encode_binary(data)
        cv2.imwrite(output_file, new_img)

        # Clean up temporary files
        if os.path.isfile(data):
            os.remove(data)
            self.print_message(f"Temporary file {data} has been removed.", is_debug=True)

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

    def decrypt_binary_arcfour(self, key_bytes, data):
        self.print_message("Decrypting data using binary RC4 algorithm", is_debug=True)
        salt = data[:16]
        ciphertext = data[16:]
        return binary_arcfour.decrypt(key_bytes, salt, ciphertext)

    def decrypt_message(self, input_image, key):
        self.print_message("Decrypting message from the image")
        self.print_message(f"Input image: {input_image}", is_debug=True)
        self.print_message(f"Cipher key: {key}", is_debug=True)
        steg = LSBSteg(cv2.imread(input_image))
        binary_data = steg.decode_binary()
        try:
            decrypted_message_bytes = self.decrypt_binary_arcfour(key.encode('utf-8'), binary_data)
            decrypted_message = decrypted_message_bytes.decode('utf-8')
            return decrypted_message
        except UnicodeDecodeError:
            print("Error: Invalid key or message data.")
            sys.exit(1)

    def add_temp_file(self, temp_file):
        self.temp_files.append(temp_file)

    def cleanup_temp_files(self):
        for temp_file in self.temp_files:
            try:
                os.remove(temp_file)
                self.print_message(f"Temporary file {temp_file} has been removed.", is_debug=True)
            except Exception as e:
                self.print_message(f"Error removing temporary file {temp_file}: {e}", is_debug=True)

        temp_data_file = os.path.join(self.temp_dir, "ciphertext.bin")
        try:
            os.remove(temp_data_file)
            self.print_message(f"Temporary file {temp_data_file} has been removed.", is_debug=True)
        except Exception as e:
            self.print_message(f"Error removing temporary file {temp_data_file}: {e}", is_debug=True)

        try:
            if os.path.isdir(self.temp_dir) and not os.listdir(self.temp_dir):
                os.rmdir(self.temp_dir)
                self.print_message("Temporary directory has been removed.", is_debug=True)
        except Exception as e:
            self.print_message(f"Error removing temporary directory: {e}", is_debug=True)



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
                        help="Use a custom key for encoding/decoding. Cannot be used with -kF.")
    parser.add_argument("-kF", "--key-file", metavar="<key_file>",
                        help="Path to the key file for decoding")
    parser.add_argument("-kS", "--key-strength", type=int, choices=range(10), default=4,
                        help="Specify the strength level of the generated key (0-9). Default: 4.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-vv", "--debug", action="store_true", help="Enable debug output")

    args = parser.parse_args()

    stegocats = StegoCats(verbose=args.verbose, debug=args.debug)

    if args.verbose or args.debug:
        print("Verbose output enabled.")

    if args.debug:
        print("Debug output enabled. Debugging information will be printed.")

    if args.key:
        stegocats.validate_user_key(args.key)

    if not args.key:
        generated_key = stegocats.generate_key(args.key_strength)

    if args.action == "encode":
        if not args.output_file:
            input_filename = os.path.splitext(os.path.basename(args.input_image))[0]
            args.output_file = os.path.join("output", input_filename + "_encoded.png")

        if args.key:
            key = str(args.key)
            if len(key) < 6:
                print("Error: The custom key must be at least 6 characters long.")
                sys.exit(1)
            else:
                stegocats.save_key_to_file(key, args.output_file)
                print("Key:", key)
        else:
            key = generated_key
            if args.output_file:
                stegocats.save_key_to_file(key, args.output_file)
                print("Key:", key)

        with open(args.input_file, 'rb') as f:
            plaintext_data = f.read()

        ciphertext = stegocats.encrypt_message(key, plaintext_data)

        temp_data_file = os.path.join(stegocats.temp_dir, "ciphertext.bin")
        with open(temp_data_file, 'wb') as f:
            f.write(ciphertext)

        resized_image_name = stegocats.resize_image(args.input_image, max_size=100000)

        with open(temp_data_file, "rb") as f:
            data = f.read()

        stegocats.hide_message(resized_image_name, key, data, args.output_file)

        print('Image saved as ' + os.path.abspath(args.output_file))

    elif args.action == "decode":
        if args.key:
            key = args.key
            if len(key) < 6:
                print("Error: The custom key must be at least 6 characters long.")
                sys.exit(1)
        else:
            if args.key_file:
                key_file_path = os.path.abspath(args.key_file)
                if not os.path.isfile(key_file_path):
                    print("Error: The specified key file does not exist.")
                    sys.exit(1)
                key = stegocats.read_key(key_file_path)
            else:
                print("Error: No key provided for decryption.")
                sys.exit(1)

        decrypted_message = stegocats.decrypt_message(args.input_image, key)
        print(decrypted_message)

    stegocats.cleanup_temp_files()


if __name__ == "__main__":
    main()
