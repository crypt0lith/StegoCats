# StegoCats - Image Steganography Tool

Author: crypt0lith

**StegoCats** is a command-line image steganography tool that allows you to hide secret messages in images using the Least Significant Bit (LSB) steganography technique. The tool supports both encryption and decryption of hidden messages and provides various options for customizing the key generation process.

## Installation

To use StegoCats, you can clone the repository:

```shell
git clone https://github.com/crypt0lith/StegoCats.git
```

After cloning the repository, install the required dependencies:

```shell
pip install -r requirements.txt
```

## Usage

### Encode a Message

To encode a message into an image, use the `encode` mode with the following options:
```shell
stegocats.py encode -i <input_image> -f <input_file> -o <output_file> -k <key>
```

**Options:**
- `-i`, `--input-image`: Path to the input image (required).
- `-f`, `--input-file`: Path to the input text file for encoding (required).
- `-o`, `--output-file`: Path to the output image file for encoding (optional). If not provided, a default output filename will be used.
- `-k`, `--key`: Use a custom key for encoding. Cannot be used with -kF.
- `-kS`, `--key-strength`: Specify the strength level of the generated key (0-9). Default: 5 (128-bit key).
### Decode a Message

To decode a message from an encoded image, use the `decode` mode with the following options:
```shell
stegocats.py decode -i <input_image> -k <key> -kF <key_file> --output-result <output_result>
```

**Options:**
- `-i`, `--input-image`: Path to the input image (required).
- `-k`, `--key`: Use a custom key for decryption. The key must be at least 6 characters long (optional).
- `-kF`, `--key-file`: Path to the key file for decoding (optional).
- `--output-result`: Path to the output file for the decoded result (optional). If not provided, the result will be printed to the console.
### Key Strength Levels

The `-kS` option allows you to specify the strength level of the generated key. Key strength levels are on a scale from 0 to 9, where 0 is the weakest but still secure, 4 is medium secure (default), and 9 is almost unbreakable (maximum-entropy). The strength levels represent levels of effectiveness vs computational overhead based on the scale.

### Validating User-Inputted Keys

The script performs input sanitization and validation for user-inputted keys to ensure the integrity of the application. Keys are checked for problematic characters that could lead to injection attacks.

## Example Usage

### Encoding a Message:

```shell
stegocats.py encode -i input_image.png -f secret_message.txt -o encoded_image.png -kS 9
```

### Decoding a Message:

```shell
stegocats.py decode -i encoded_image.png -k my_secret_key --output-result decrypted_message.txt
```

## More Examples

### Python Code Payload:
#### Encoding a Python Code Payload in an Image
This example demonstrates how to encode a Python code payload into an image with a custom key strength of 9.

```shell
stegocats.py encode -i images/hacker.png -f data/python.txt -kS 9 -o output/hacker_encoded_payload.png
```
In this example:

- The `images/hacker.png` image is used as the input image.
- The `data/python.txt` file contains the Python code payload to be encoded.
    + `python.txt`  begins with a '`# python`' flag so StegoCats will recognize it as Python code.
      
    + Link to `python.txt`  [here](https://github.com/crypt0lith/StegoCats/blob/master/examples/python_payload/data/python.txt).
      
- The `-kS 9` option specifies a custom key strength level of 9 for key generation.
- The `-o output/hacker_encoded_payload.png` option sets the output image filename to `output/hacker_encoded_payload.png`.
- StegoCats embeds the Python code payload into the image using the LSB steganography technique and saves the output image.

#### Decoding the Python Code Payload
After encoding the Python code payload, you can use the following command to decode it:

```shell
stegocats.py decode -i output/hacker_encoded_payload.png -kF data/hacker_encoded_payload.key -y --output-result output/hacker_payload_response.txt
```
In this example:

- The `output/hacker_encoded_payload.png` image, which contains the encoded Python code payload, is used as the input image.
- The `-kF data/hacker_encoded_payload.key` option specifies the path to the key file used for decryption.
- The `-y` option automatically answers "yes" to prompts, in this case executing Python code in the payload.
- The `--output-result output/hacker_payload_response.txt` option sets the output filename to `output/hacker_payload_response.txt`. 
- StegoCats decrypts the hidden data, detects Python code, executes it, and saves the output of the executed code to `output/hacker_payload_response.txt`.

## Security Considerations:

- The strength of the encryption relies on the complexity and length of the key. Use a strong key to ensure security.
- Always keep the key secret and don't share it with unauthorized parties.
- Ensure that the input image and output image are in a format that supports lossless compression to avoid data loss during encoding.

## Disclaimer:

This tool is intended for educational and legitimate purposes only. The author is not responsible for any misuse or illegal activities that may arise from using this tool. Please use it responsibly and in compliance with applicable laws and regulations.
