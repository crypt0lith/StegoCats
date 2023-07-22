import random

MOD = 256

def KSA(key):
    key_length = len(key)
    S = list(range(MOD))
    j = 0
    for i in range(MOD):
        j = (j + S[i] + key[i % key_length]) % MOD
        S[i], S[j] = S[j], S[i]
    return S

def PRGA(S, data_length):
    i = 0
    j = 0
    keystream = bytearray()
    for _ in range(data_length):
        i = (i + 1) % MOD
        j = (j + S[i]) % MOD

        S[i], S[j] = S[j], S[i]  # swap values
        K = S[(S[i] + S[j]) % MOD]
        keystream.append(K)

    return bytes(keystream)

def get_keystream(key, salt, data_length):
    key_with_salt = key + salt
    S = KSA(key_with_salt)
    return iter(PRGA(S, data_length))

def encrypt_logic(key, salt, data):
    data_length = len(data)
    key_stream = get_keystream(key, salt, data_length)
    encrypted_data = bytearray()
    for byte in data:
        encrypted_byte = byte ^ next(key_stream)
        encrypted_data.append(encrypted_byte)
    return bytes(encrypted_data)

def encrypt(key, salt, data):
    return encrypt_logic(key, salt, data)

def decrypt(key, salt, data):
    return encrypt_logic(key, salt, data)

def main():
    key = b'not-so-random-key'  # Use bytes for binary data
    salt = bytes([random.randint(0, 255) for _ in range(16)])  # Generate random salt (16 bytes)
    data = b'\x01\x23\x45\x67\x89\xAB\xCD\xEF'  # Binary data

    encrypted_data = encrypt(key, salt, data)
    decrypted_data = decrypt(key, salt, encrypted_data)

    print('Original Data:', data)
    print('Salt:', salt)
    print('Encrypted Data:', encrypted_data)
    print('Decrypted Data:', decrypted_data)

if __name__ == '__main__':
    main()
