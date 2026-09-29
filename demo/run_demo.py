from server.crypto import encrypt
from server.padding import unpad

from attacker.oracle import PaddingOracle
from attacker.attack import padding_oracle_attack


SERVER_URL = "http://127.0.0.1:5000/decrypt"
IV = b"AAAAAAAAAAAAAAAA"


def main():
    print("=" * 60)
    print("PADDING ORACLE ATTACK DEMO")
    print("=" * 60)

    plaintext = b"Attack at dawn!"

    print()
    print("[SERVER]")
    print(f"Original plaintext: {plaintext!r}")

    ciphertext = encrypt(plaintext, IV)

    full_ciphertext = IV + ciphertext

    print()
    print("[ATTACKER]")
    print(f"IV + ciphertext: {full_ciphertext.hex()}")

    print()
    print("[*] Starting padding oracle attack...")

    oracle = PaddingOracle(SERVER_URL)

    recovered_padded = padding_oracle_attack(
        oracle,
        full_ciphertext
    )

    recovered = unpad(recovered_padded)

    print()
    print("=" * 60)
    print("RESULT")
    print("=" * 60)

    print(f"Original plaintext : {plaintext!r}")
    print(f"Recovered plaintext: {recovered!r}")

    if recovered == plaintext:
        print()
        print("[+] Attack successful!")
    else:
        print()
        print("[-] Attack failed.")


if __name__ == "__main__":
    main()