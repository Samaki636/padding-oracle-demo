from attacker.oracle import PaddingOracle

# CBC blocks are 16 bytes.
BLOCK_SIZE = 16


def recover_block(
    oracle: PaddingOracle,
    previous_block: bytes,
    target_block: bytes
) -> bytes:
    """
    Recover the plaintext of target_block using a padding oracle.

    The attacker knows:
        previous_block
        target_block

    The attacker does NOT know:
        AES key
        intermediate state

    Returns:
        Recovered plaintext block.
    """

    if len(previous_block) != BLOCK_SIZE:
        raise ValueError("previous_block must be 16 bytes")

    if len(target_block) != BLOCK_SIZE:
        raise ValueError("target_block must be 16 bytes")

    intermediate = bytearray(BLOCK_SIZE)
    plaintext = bytearray(BLOCK_SIZE)

    # Recover bytes from right to left.
    for position in range(BLOCK_SIZE - 1, -1, -1):

        padding_value = BLOCK_SIZE - position

        # Start from the original previous block.
        modified_block = bytearray(previous_block)

        # Force already recovered bytes to produce
        # the current padding value.
        for index in range(position + 1, BLOCK_SIZE):
            modified_block[index] = (
                intermediate[index] ^ padding_value
            )

        found = False

        # Try all possible byte values.
        for guess in range(256):

            modified_block[position] = guess

            crafted_ciphertext = (
                bytes(modified_block) +
                target_block
            )

            if oracle.query(crafted_ciphertext):

                intermediate[position] = (
                    guess ^ padding_value
                )

                plaintext[position] = (
                    intermediate[position]
                    ^ previous_block[position]
                )

                print(
                    f"[+] Byte {position:02d}: "
                    f"0x{plaintext[position]:02x} "
                    f"({chr(plaintext[position])!r})"
                )

                found = True
                break

        if not found:
            raise RuntimeError(
                f"Could not recover byte at position {position}"
            )

    return bytes(plaintext)


def padding_oracle_attack(
    oracle: PaddingOracle,
    ciphertext: bytes
) -> bytes:
    """
    Recover plaintext from an IV || ciphertext value.

    The ciphertext can contain multiple AES blocks.
    """

    if len(ciphertext) < 32:
        raise ValueError(
            "Ciphertext must contain at least IV + one block"
        )

    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError(
            "Ciphertext length must be a multiple of 16 bytes"
        )

    blocks = [
        ciphertext[i:i + BLOCK_SIZE]
        for i in range(0, len(ciphertext), BLOCK_SIZE)
    ]

    recovered = bytearray()

    # The first block is the IV.
    # For every ciphertext block C_i,
    # the attacker uses C_(i-1) to manipulate the plaintext.
    for block_index in range(1, len(blocks)):

        previous_block = blocks[block_index - 1]
        target_block = blocks[block_index]

        print()
        print(f"[*] Recovering block {block_index}")
        print(f"    Previous block: {previous_block.hex()}")
        print(f"    Target block:   {target_block.hex()}")

        plaintext_block = recover_block(
            oracle,
            previous_block,
            target_block
        )

        recovered.extend(plaintext_block)

        print(
            f"[+] Recovered block: "
            f"{plaintext_block!r}"
        )

    return bytes(recovered)