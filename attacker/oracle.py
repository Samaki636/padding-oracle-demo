import requests


class PaddingOracle:
    """
    Client-side interface to the vulnerable padding oracle.

    The attacker can only submit ciphertexts and observe whether
    the server reports valid or invalid padding.
    """

    def __init__(self, url: str):
        self.url = url

    def query(self, ciphertext: bytes) -> bool:
        """
        Submit a ciphertext to the server.

        Returns:
            True  -> padding is valid
            False -> padding is invalid
        """

        response = requests.post(
            self.url,
            json={
                "ciphertext": ciphertext.hex()
            },
            timeout=5
        )

        return response.status_code == 200