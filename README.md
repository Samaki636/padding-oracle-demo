# Padding Oracle Attack Demo

A small educational implementation of a **Padding Oracle Attack** against AES-CBC with PKCS#7 padding.

The project demonstrates how an attacker can recover plaintext **without knowing the encryption key**, by exploiting a server that reveals whether the decrypted ciphertext contains valid padding.

> **Educational purpose:** this project intentionally implements a vulnerable server to demonstrate the mechanics of a padding oracle attack. It should not be used in production.

## Architecture

The project is divided into three components:

```text
padding-oracle-demo/
├── server/
│   ├── app.py
│   ├── crypto.py
│   └── padding.py
│
├── attacker/
│   ├── oracle.py
│   └── attack.py
│
├── demo/
│   └── run_demo.py
│
└── requirements.txt
```

* **`server/`** — vulnerable Flask server implementing AES-CBC decryption and PKCS#7 padding validation.
* **`attacker/`** — implementation of the padding oracle and the attack algorithm.
* **`demo/`** — runs the complete attack and displays the recovered plaintext.

## Requirements

* Python 3.10+
* Flask
* PyCryptodome
* Requests

## Installation

Clone the repository and install the dependencies:

```bash
pip install -r requirements.txt
```

## Run

Start the vulnerable server:

```bash
python -m server.app
```

In a second terminal, run the attack:

```bash
python -m demo.run_demo
```

The attacker communicates with the server through the `/decrypt` endpoint.

## Attack Principle

AES-CBC decryption for a ciphertext block can be written as:

$$
P_i = D_K(C_i) \oplus C_{i-1}
$$

where:

* \(K\) is the secret AES key
* \(C_i\) is the current ciphertext block
* \(C_{i-1}\) is the previous ciphertext block
* \(I_i = D_K(C_i)\) is the intermediate value
* \(P_i\) is the plaintext block

The attacker does **not** know \(K\) or \(I_i\).

However, the attacker can modify \(C_{i-1}\) and send the resulting ciphertext to the server.

If the server reveals whether the resulting plaintext has valid PKCS#7 padding, this response acts as a **padding oracle**.

### Recovering a byte

For the last byte of a block, the attacker tries different values for a modified previous block \(C'_{i-1}\).

The goal is to force:

$$
P'_i = 01
$$

Since:

$$
P'_i = I_i \oplus C'_{i-1}
$$

and XOR is reversible:

$$
I_i = P'_i \oplus C'_{i-1}
$$

Therefore, when the oracle reports valid padding:

$$
I_i = 01 \oplus C'_{i-1}
$$

The original plaintext byte can then be recovered using:

$$
P_i = I_i \oplus C_{i-1}
$$

The same process is repeated from **right to left** for every byte of the block.

## Attack Flow

```text
Original ciphertext
        │
        ▼
Modify previous ciphertext block
        │
        ▼
Send modified ciphertext to /decrypt
        │
        ▼
Server decrypts with secret key
        │
        ▼
PKCS#7 padding validation
        │
   ┌────┴────┐
   │         │
Valid      Invalid
   │         │
   ▼         ▼
200 OK     400
   │
   ▼
Recover intermediate byte
   │
   ▼
Recover plaintext byte
```

The attack requires multiple oracle queries. For each plaintext byte, the implementation tries up to **256 possible byte values**.

Importantly, this is **not a brute-force attack against the AES key**. The key remains unknown throughout the entire process.

## Example

The demo progressively prints the recovered plaintext bytes:

```text
[*] Recovering block 1
    Previous block: ...
    Target block:   ...

[+] Byte 15: 0x01 ('\x01')
[+] Byte 14: 0x65 ('e')
[+] Byte 13: 0x67 ('g')
...
```

At the end, the recovered plaintext can be compared with the original plaintext.

## Why the Attack Works

The vulnerability does not come from AES itself.

AES-CBC correctly provides confidentiality when used appropriately. The problem is the combination of:

1. CBC mode allowing controlled modifications of the previous ciphertext block.
2. PKCS#7 padding being checked after decryption.
3. The server revealing whether the padding is valid or invalid.

Even a single bit of information — **valid or invalid padding** — can be enough to recover the plaintext through repeated queries.

## Mitigation

A padding oracle should not be exposed by an application.

Typical mitigations include:

* Use authenticated encryption such as **AES-GCM** or another AEAD mode.
* Do not expose different error messages for padding, authentication, or decryption failures.
* Keep error responses and observable behavior as uniform as possible.
* Verify authentication before accepting decrypted plaintext when using an authenticated encryption design.

## Disclaimer

This repository is intended for **educational and security research purposes**. The vulnerable server is deliberately designed to expose the behavior required for demonstrating a Padding Oracle Attack.
