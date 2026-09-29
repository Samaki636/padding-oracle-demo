from Crypto.Cipher import AES

from server.padding import pad, unpad


BLOCK_SIZE = 16

# Key known only by the server.
KEY = b"0123456789ABCDEF"


def encrypt(plaintext: bytes, iv: bytes) -> bytes:
    """
    Encrypt plaintext using AES-CBC.
    """

    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be 16 bytes long")

    padded = pad(plaintext, BLOCK_SIZE)

    cipher = AES.new(KEY, AES.MODE_CBC, iv)

    return cipher.encrypt(padded)


def decrypt(ciphertext: bytes, iv: bytes) -> bytes:
    """
    Decrypt ciphertext using AES-CBC and verify the padding.
    """

    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be 16 bytes long")

    if len(ciphertext) == 0:
        raise ValueError("Empty ciphertext")

    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Invalid ciphertext")

    cipher = AES.new(KEY, AES.MODE_CBC, iv)

    decrypted = cipher.decrypt(ciphertext)

    return unpad(decrypted, BLOCK_SIZE)