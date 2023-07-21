# StegoCats - Image Steganography Tool

**StegoCats** is a command-line image steganography tool that allows you to hide secret messages in images using the Least Significant Bit (LSB) steganography technique. The tool supports both encryption and decryption of hidden messages and provides various options for customizing the key generation process.

## Installation

1. Clone the repository:
```shell
git clone https://github.com/crypt0lith/StegoCats.git
```

2. Install the required dependencies:
```shell
pip install -r requirements.txt
```

## Usage

### Encode a Message:

To encode a message into an image, use the `encode` action with the following options:
```shell
python stegocats.py -a encode -i <input_image> -f <input_file> -o <output_file> -k <key>
```

**Options:**
- `-i`, `--input-image`: Path to the input image (required).
- `-f`, `--input-file`: Path to the input text file containing the message to be encoded (required).
- `-o`, `--output-file`: Path to the output image file (optional). If not provided, a default output filename will be used.
- `-k`, `--key`: Use a custom key for encryption. The key must be at least 6 characters long (optional).
- `-kS`, `--key-strength`: Specify the strength level of the generated key (0-9). Default: 4 (optional).


### Decode a Message:

To decode a message from an encoded image, use the `decode` action with the following options:
```shell
python stegocats.py -a decode -i <input_image> -k <key> -kF <key_file>
```

**Options:**
- `-i`, `--input-image`: Path to the input image (required).
- `-k`, `--key`: Use a custom key for decryption. The key must be at least 6 characters long (optional).
- `-kF`, `--key-file`: Path to the key file for decryption (optional).

### Key Strength Levels:

The `-kS` option allows you to specify the strength level of the generated key. Key strength levels are on a scale from 0 to 9, where 0 is the weakest but still secure, 4 is the default level and generates a strong key, and 9 is basically unbreakable (maximum-entropy). The strength levels represent levels of effectiveness vs computational overhead based on the scale. Each consecutive level reflects an escalation of key complexity requirements. Nobody's going to find the ciphertext you hid in that cat meme anyway, but even if they did they still wouldn't be able decrypt it.

### Validating User-Inputted Keys:

The script performs input sanitization and validation for user-inputted keys to ensure the integrity of the application. Keys are checked for problematic characters that could lead to injection attacks.

## Example Usage:

### Encoding a Message:
```shell
python stegocats.py -a encode -i input_image.png -f secret_message.txt -o encoded_image.png -kS 9
```

### Decoding a Message:
```shell
python stegocats.py -a decode -i encoded_image.png -k my_secret_key
```

## Security Considerations:

- The strength of the encryption relies on the complexity and length of the key. Use a strong key to ensure security.
- Always keep the key secret and don't share it with unauthorized parties.
- Ensure that the input image and output image are in a format that supports lossless compression to avoid data loss during encoding.

## Disclaimer:

This tool is intended for educational and legitimate purposes only. The author is not responsible for any misuse or illegal activities that may arise from using this tool. Please use it responsibly and in compliance with applicable laws and regulations.
