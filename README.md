![G5LIVE — Build · Understand · Apply](assets/brand/g5live.svg)

# Crypto Lab Tool

An evolving offline encryption, decryption, and hashing multi-tool, starting from three completed cryptography exercises. Python 3.8+ and PyCryptodome are required. No HTTP requests, wordlist loops, embedded room answers, keys, or personal paths.

## Setup

Open this directory as a PyCharm project. Create a project virtual environment and install `requirements.txt`, or run:

```sh
python -m pip install -r requirements.txt
python crypto_tool.py --help
python -m unittest -v
```

## Commands

Textbook RSA with known factors (decimal integers or 0x-prefixed hex):

```sh
python crypto_tool.py rsa --p 61 --q 53 --e 17 --ciphertext 2790
```

This outputs plaintext hex `41` (ASCII A). It checks distinct prime factors and exponent invertibility. It does not factor a modulus, break arbitrary RSA, parse PEM files, or remove OAEP/PKCS#1 padding. Leading zero bytes cannot be recovered from an integer without an external message length. Private exponents are never printed.

AES-CBC encryption, with a raw binary key file containing exactly 16, 24, or 32 bytes:

```sh
python crypto_tool.py aes-encrypt --input message.bin --key-file key.bin
```

Output is JSON containing `data_base64` and `iv_hex`. A fresh random IV is generated unless `--iv-hex` is supplied for reproducible exercises. To decrypt, decode `data_base64` into a binary ciphertext file, then run:

```sh
python crypto_tool.py aes-decrypt --input ciphertext.bin --key-file key.bin --iv-hex YOUR_IV_HEX
```

Decrypted bytes are returned as `data_base64`; they are not assumed to be UTF-8. Keys are read from files to keep them out of command arguments. Outputs may contain sensitive plaintext and should be handled accordingly.

CBC IV modification:

```sh
python crypto_tool.py flip-iv --token YOUR_TOKEN --encoding hex --offset 0 --original-hex 30 --replacement-hex 31
```

Requires a token encoded as `IV || ciphertext`. Offset is a byte position in the first plaintext block. Original and replacement bytes must have equal lengths and fit in that block. The change applies `IV[i] ^= original[i] ^ replacement[i]`. It does not discover or verify the original plaintext, decrypt the token, update later blocks, or generate a valid authentication tag. Hex 30 and 31 represent ASCII 0 and 1; their XOR is 01, as in the original exercise.

CBC alone does not authenticate messages. Correct padding does not prove that a key or message is correct. For new applications, use an authenticated mode such as GCM or EAX rather than this teaching tool.

Sources: https://www.pycryptodome.org/src/cipher/classic and https://www.pycryptodome.org/src/cipher/modern

## Review of the original scripts

- `rsa_key_decipher.py`: correct textbook RSA formula for distinct primes and an invertible exponent. Room-specific factors and ciphertext were embedded; it printed the private exponent, ran on import, assumed UTF-8 plaintext, and imported unused SymPy factoring code. Sanitised into the `rsa` command; no factor service is used.
- `aes_key_decryption.py`: actually encrypted candidate words with a known key, then posted them to a fixed room endpoint. This was message guessing, not AES-key recovery or decryption. The script embedded a key, endpoint and local wordlist path; loaded the full wordlist; lacked request timeout/error handling; and used a brittle response-string match. The HTTP guessing workflow has been removed. Local AES-CBC encryption is retained and local decryption added.
- `bit_flip_decipher.py`: modified the first IV byte by XOR 01, assuming a room-specific token layout and plaintext position. It could crash on missing arguments or short tokens, and printed room-specific browser instructions. Replaced with validated token decoding, explicit offset and equal-length byte replacements.

The three original standalone scripts were retired after consolidation. No original embedded room values are retained in this repository. IDE metadata, virtual environments, unrelated files, and version-control history are outside this sanitisation.

## Hashing and verification

```sh
python crypto_tool.py hash --input example.bin
python crypto_tool.py hash --input example.bin --algorithm sha512
python crypto_tool.py hash --input example.bin --expected EXPECTED_SHA256_HEX
```

Files are read in chunks. SHA-256 is the default; SHA-512, SHA3-256, BLAKE2b, SHA-1, and MD5 are also supported. MD5 and SHA-1 are for legacy checksum compatibility, not security-sensitive use. Hash verification exits with 0 for a match, 1 for a mismatch, and 2 for invalid input or an operational error. Hashes cannot be decrypted and this tool does not crack password hashes.

## Development roadmap

- Add authenticated encryption and decryption with AES-GCM.
- Add direct binary output and a documented encrypted-file format.
- Add standard RSA key files and OAEP encryption/decryption.
- Split the CLI and cryptographic operations into a package as it grows.
- Expand malformed-input tests and release documentation.

Existing RSA and CBC operations are educational primitives, not a production file-encryption format. The project grew from self-written TryHackMe exercises; the implementation has been sanitised and refactored, with no room flags or answers included.

## Shared brand and release preparation

Part of the G5LIVE app family. See the [shared brand guide](assets/brand/BRAND.md) and [project-specific release-readiness review](docs/RELEASE_READINESS.md) for proposed functionality and public-release preparation.
