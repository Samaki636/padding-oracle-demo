BLOCK_SIZE = 16


def pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """
    Apply PKCS#7 padding to the data.
    """

    padding_length = block_size - (len(data) % block_size)

    padding = bytes([padding_length]) * padding_length

    return data + padding


def unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """
    Remove and verify PKCS#7 padding.

    Raises ValueError if the padding is invalid.
    """

    if not data:
        raise ValueError("Invalid padding: empty data")

    if len(data) % block_size != 0:
        raise ValueError("Invalid padding: data length is not a multiple of the block size")

    padding_length = data[-1]

    if padding_length < 1 or padding_length > block_size:
        raise ValueError("Invalid padding")

    padding = data[-padding_length:]

    if padding != bytes([padding_length]) * padding_length:
        raise ValueError("Invalid padding")

    return data[:-padding_length]