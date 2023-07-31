# author: crypt0lith

import argparse
import os
import secrets
import string
import sys
import tempfile
import webbrowser
import re
import io
import zlib

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
        problematic_characters = ['\\', '"', "'", ';', ':', '*', '&', '|', '`', '$']
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
            9: 64
        }

        if key_strength in key_strength_levels:
            key_length = key_strength_levels[key_strength]

        generated_key = ''.join(secrets.choice(safe_characters) for _ in range(key_length))
        return generated_key

    def save_key_to_file(self, key, output_file):
        key_hex = key.encode('utf-8').hex()
        key_file_name = os.path.abspath(
            os.path.join("data", os.path.basename(output_file).replace('.png', '.key').replace('.jpg', '.key')))
        with open(key_file_name, 'w') as f:
            f.write(key_hex)
        print("Key saved as:", key_file_name)

    def read_plaintext_file(self, input_file):
        with open(input_file) as f:
            return ' '.join(line.strip() for line in f)

    def read_key(self, key_file):
        with open(key_file, 'r') as f:
            key_hex = f.read().strip()
        try:
            key_bytes = bytes.fromhex(key_hex)
            key = key_bytes.decode('utf-8')
            return key
        except ValueError:
            print("Error: The key is not in a valid hexadecimal format.")
            sys.exit(1)

    def compress_data(self, data):
        # Compression using zlib
        return zlib.compress(data)

    def encrypt_binary_arcfour(self, key_bytes, data):
        # Compression using zlib
        compressed_data = self.compress_data(data)

        # Encryption using RC4
        salt = os.urandom(16)  # Generate a random 16-byte salt
        ciphertext = binary_arcfour.encrypt(key_bytes, salt, compressed_data)

        return salt + ciphertext  # Return the concatenated salt and ciphertext

    def encrypt_message(self, key, plaintext_data):
        key_bytes = key.encode('utf-8')
        plaintext_bytes = plaintext_data
        self.print_message(f"Plaintext: {plaintext_bytes}")
        self.print_message(f"Cipher key: {key_bytes}", is_debug=True)
        self.print_message(f"Hash of the key: {hash(key_bytes)}", is_debug=True)
        ciphertext_bytes = self.encrypt_binary_arcfour(key_bytes, plaintext_bytes)
        self.print_message(f"Ciphertext: {ciphertext_bytes}")
        return ciphertext_bytes

    def decompress_data(self, data):
        # Decompression using zlib
        return zlib.decompress(data)

    def decrypt_binary_arcfour(self, key_bytes, data):
        # Decryption using RC4
        salt = data[:16]  # Extract the salt (first 16 bytes) from the input data
        ciphertext = data[16:]  # Extract the ciphertext (remaining bytes) from the input data
        compressed_data = binary_arcfour.decrypt(key_bytes, salt, ciphertext)

        # Decompression using zlib
        decompressed_data = self.decompress_data(compressed_data)
        return decompressed_data

    def decrypt_message(self, input_image, key):
        # Function to decrypt hidden data from an image using the provided key
        self.print_message("Decrypting message from the image")
        self.print_message(f"Input image: {input_image}", is_debug=True)
        self.print_message(f"Cipher key: {key}", is_debug=True)
        steg = LSBSteg(cv2.imread(input_image))  # Initialize the LSBSteg class with the input image
        binary_data = steg.decode_binary()  # Extract the hidden binary data from the image
        try:
            decrypted_message_bytes = self.decrypt_binary_arcfour(key.encode('utf-8'), binary_data)
            decrypted_message = decrypted_message_bytes.decode('utf-8')
            return decrypted_message
        except UnicodeDecodeError:
            print("Error: Invalid key or message data.")
            sys.exit(1)

    def execute_python_code(self, code):
        # Remove the "# python" part and any leading/trailing whitespaces
        code = code.replace("# python", "").strip()

        # Execute the Python code
        try:
            exec(code, globals(), locals())
        except Exception as e:
            print(f"Error while executing Python code: {e}")

    def calculate_max_embedded_size(self, input_image, data_size):
        # Function to calculate the maximum size that can be embedded in the input image
        with Image.open(input_image) as image:
            # Get the image format and compression quality
            image_format = image.format.lower()
            compression_quality = 100  # Default quality (100% - lossless)

            if image_format in ["jpeg", "jpg"]:
                # For JPEG format, get the compression quality
                if "quality" in image.info:
                    compression_quality = image.info["quality"]
                else:
                    # If quality information is not available, assume maximum quality
                    compression_quality = 100

            # Calculate the maximum embedded size based on the image size, format, and compression quality
            max_embedded_size = (image.width * image.height * (compression_quality / 100) * 3) // 8

            if max_embedded_size < data_size:
                raise ValueError("Data size exceeds the available space in the input image")

            return max_embedded_size

    def resize_image(self, input_image, max_embedded_size):
        # Function to resize an image while maintaining the aspect ratio and ensuring the output size does not exceed
        # max_embedded_size
        with tempfile.NamedTemporaryFile(suffix='.png', dir=self.temp_dir, delete=False) as temp_image:
            # Create a temporary image file with .png extension
            output_name = temp_image.name
            with Image.open(input_image) as image:
                aspect_ratio = image.width / image.height

                # A dictionary with common aspect ratios and their corresponding width-to-height ratios
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

                # Shrink the image iteratively to reduce the size
                while True:
                    resized_image = image.copy()
                    resized_image.thumbnail((new_width, new_height), Image.LANCZOS)
                    resized_image.save(output_name, format="PNG", optimize=True)
                    output_size = os.path.getsize(output_name)

                    if output_size > max_embedded_size:
                        break

                    new_width *= 2
                    new_height *= 2

            # Resize one last time to fit within the max_embedded_size
            final_resized_image = image.copy()
            final_resized_image.thumbnail((new_width // 2, new_height // 2), Image.LANCZOS)
            final_resized_image.save(output_name, format="PNG", optimize=True)

        self.temp_files.append(output_name)
        return output_name

    def hide_message(self, input_image, key, data, output_file):
        # Function to hide binary data in an image using the LSB (Least Significant Bit) method
        self.print_message("Hiding message in the image")
        self.print_message(f"Input image: {input_image}", is_debug=True)
        self.print_message(f"Output image: {output_file}", is_debug=True)
        steg = LSBSteg(cv2.imread(input_image))  # Initialize the LSBSteg class with the input image
        new_img = steg.encode_binary(data)  # Embed the binary data in the image using LSB
        cv2.imwrite(output_file, new_img)  # Save the steganographic image

        # Clean up temporary files
        if os.path.isfile(data):
            os.remove(data)
            self.print_message(f"Temporary file {data} has been removed.", is_debug=True)

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
    parser.add_argument("mode", choices=["encode", "decode"],
                        help="Select 'encode' to hide data in an image or 'decode' to extract data from an image")
    parser.add_argument("-i", "--input-image", required=True, metavar="<input_image>",
                        help="Path to the input image")

    # Grouping the encoding-related arguments together
    encoding_group = parser.add_argument_group("Encoding options")
    encoding_group.add_argument("-f", "--input-file", metavar="<input_file>",
                                help="Path to the input text file for encoding")
    encoding_group.add_argument("-o", "--output-file", metavar="<output_file>",
                                help="Path to the output image file for encoding")
    encoding_group.add_argument("-k", "--key", metavar="<key>",
                                help="Use a custom key for encoding. Cannot be used with -kF.")
    encoding_group.add_argument("-kS", "--key-strength", type=int, choices=range(10), default=4,
                                help="Specify the strength level of the generated key (0-9). Default: 4.")

    # Grouping the decoding-related arguments together
    decoding_group = parser.add_argument_group("Decoding options")
    decoding_group.add_argument("-kF", "--key-file", metavar="<key_file>",
                                help="Path to the key file for decoding")
    decoding_group.add_argument("--output-result", metavar="<output_result>",
                                help="Path to the output file for the decoded result")
    decoding_group.add_argument("-y", "--yes", action="store_true",
                                help="Automatically answer yes to prompts (e.g., execute Python code, open hyperlinks).")
    decoding_group.add_argument("-n", "--no", action="store_true",
                                help="Automatically answer no to prompts (e.g., execute Python code, open hyperlinks).")

    # Common options for both encoding and decoding
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-vv", "--debug", action="store_true", help="Enable debug output")

    args = parser.parse_args()

    # Initialize the StegoCats class with verbosity and debug settings based on command-line arguments
    stegocats = StegoCats(verbose=args.verbose, debug=args.debug)

    if args.verbose or args.debug:
        print("Verbose output enabled.")

    if args.debug:
        print("Debug output enabled. Debugging information will be printed.")

    if args.key:
        # Validate the user-provided key for problematic characters
        stegocats.validate_user_key(args.key)

    if not args.key:
        # If no key is provided, generate a random key based on the specified key_strength
        generated_key = stegocats.generate_key(args.key_strength)

    if args.mode == "encode":
        # Perform the encoding operation

        # Check if the input file is provided for encoding
        if not args.input_file:
            print("Error: You must provide an input file (-f) for encoding.")
            sys.exit(1)

        if not args.output_file:
            # If no output file path is provided, create an output file path based on the input image filename
            input_filename = os.path.splitext(os.path.basename(args.input_image))[0]
            args.output_file = os.path.join("output", input_filename + "_encoded.png")

        if args.key:
            # If a custom key is provided, use it for encoding
            key = str(args.key)
            if len(key) < 6:
                print("Error: The custom key must be at least 6 characters long.")
                sys.exit(1)
            else:
                # Save the custom key to a key file associated with the output image
                stegocats.save_key_to_file(key, args.output_file)
        else:
            # If no key is provided, use the randomly generated key and save it to a key file
            key = generated_key
            if args.output_file:
                stegocats.save_key_to_file(key, args.output_file)

        # Read the plaintext data from the input file
        with open(args.input_file, 'rb') as f:
            plaintext_data = f.read()

        # Encrypt the plaintext data using RC4 and hide it in the resized input image
        ciphertext = stegocats.encrypt_message(key, plaintext_data)
        temp_data_file = os.path.join(stegocats.temp_dir, "ciphertext.bin")
        with open(temp_data_file, 'wb') as f:
            f.write(ciphertext)

        # Calculate the max embedded size based on the size of the input image and the encrypted data
        data_size = os.path.getsize(temp_data_file)
        max_embedded_size = stegocats.calculate_max_embedded_size(args.input_image, data_size)

        if data_size > max_embedded_size:
            raise ValueError("Data size exceeds the available space in the input image")

        # Resize the input image and hide the encrypted data in the resized image
        resized_image_name = stegocats.resize_image(args.input_image, max_embedded_size)
        with open(temp_data_file, "rb") as f:
            data = f.read()
        stegocats.hide_message(resized_image_name, key, data, args.output_file)

        print('Image saved as ' + os.path.abspath(args.output_file))

    elif args.mode == "decode":
        # Perform the decoding operation

        if args.key:
            # If a key is provided as a command-line argument, use it for decoding
            key = args.key
            if len(key) < 6:
                print("Error: The custom key must be at least 6 characters long.")
                sys.exit(1)

        else:
            if args.key_file:
                # If a key file is provided, read the key from the file
                key_file_path = os.path.abspath(args.key_file)
                if not os.path.isfile(key_file_path):
                    print("Error: The specified key file does not exist.")
                    sys.exit(1)
                key = stegocats.read_key(key_file_path)
            else:
                # If no key or key file is provided, print an error message and exit
                print("Error: No key provided for decryption.")
                sys.exit(1)

        # Perform decryption and get the decrypted message
        decrypted_message = stegocats.decrypt_message(args.input_image, key)

        if decrypted_message.strip().startswith("# python"):
            # If the decrypted message contains Python code, prompt the user to execute it
            print("Detected Python code in the decrypted message.")

            if not args.yes and not args.no:
                print(decrypted_message)
                user_input = input("Do you want to execute the Python code? (y/n): ").lower()
                while user_input not in ['y', 'n']:
                    print("Invalid input. Please enter 'y' or 'n'.")
                    user_input = input("Do you want to execute the Python code? (y/n): ").lower()

                if user_input == 'y':
                    args.yes = True
                else:
                    args.no = True

            if args.yes:
                # Redirect stdout to a string buffer to capture the output of the executed code
                output_buffer = io.StringIO()
                sys.stdout = output_buffer

                stegocats.execute_python_code(decrypted_message)

                # Get the captured output and restore stdout
                captured_output = output_buffer.getvalue()
                sys.stdout = sys.__stdout__

                # Print the captured output
                print("Output of the executed Python code:")
                print(captured_output)

                # Save the captured output to the output file
                if args.output_result:
                    with open(args.output_result, 'w') as output_file:
                        output_file.write(captured_output)
                    print("Output saved to:", args.output_result)

            else:
                print("Python code not executed.")

        elif re.search(r'https?://\S+', decrypted_message):
            # If the decrypted message contains a URL, prompt the user to preview it
            print("Detected URL in the decrypted message:")
            url = re.search(r'https?://\S+', decrypted_message).group()
            print("URL Preview:", url[:50] + '...' if len(url) > 50 else url)

            if not args.yes and not args.no:
                user_input = input("Do you want to open the URL? (y/n): ").lower()
                while user_input not in ['y', 'n']:
                    print("Invalid input. Please enter 'y' or 'n'.")
                    user_input = input("Do you want to open the URL? (y/n): ").lower()

                if user_input == 'y':
                    args.yes = True
                else:
                    args.no = True

            if args.yes:
                webbrowser.open(url)
            else:
                print("URL not opened.")

            # Save the URL to the output file
            if args.output_result:
                with open(args.output_result, 'w') as output_file:
                    output_file.write(url)
                print("URL saved to:", args.output_result)

        else:
            # Otherwise, print the decrypted message as it is
            print("Decrypted message:")
            print(decrypted_message)

            # Save the decrypted message to the output file
            if args.output_result:
                with open(args.output_result, 'w') as output_file:
                    output_file.write(decrypted_message)
                print("Decrypted message saved to:", args.output_result)

    # Clean up temporary files and directories after performing the steganography operation
    stegocats.cleanup_temp_files()


if __name__ == "__main__":
    main()
