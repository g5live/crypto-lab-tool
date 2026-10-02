"""G5LIVE Crypto Lab Tool. Offline cryptography exercises; no embedded keys, targets, or room answers."""
import argparse
import base64
import binascii
import hashlib
import hmac
import json
import sys
from pathlib import Path


def crypto():
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad, unpad
        from Crypto.Util.number import isPrime
    except ImportError as exc:
        raise ValueError('Install the dependency: python -m pip install pycryptodome') from exc
    return AES, pad, unpad, isPrime


def decode(value, encoding):
    try:
        return bytes.fromhex(value) if encoding == 'hex' else base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError(f'Invalid {encoding} input') from exc


def rsa_decrypt(p, q, e, ciphertext):
    _, _, _, is_prime = crypto()
    if p == q or not is_prime(p) or not is_prime(q):
        raise ValueError('p and q must be distinct primes')
    n = p * q
    if not 1 < e < n or not 0 <= ciphertext < n:
        raise ValueError('Require 1 < e < n and 0 <= ciphertext < n')
    try:
        d = pow(e, -1, (p - 1) * (q - 1))
    except ValueError as exc:
        raise ValueError('e is not invertible modulo phi(n)') from exc
    message = pow(ciphertext, d, n)
    return message.to_bytes(max(1, (message.bit_length() + 7) // 8), 'big')


def aes_cbc(data, key, iv=None, decrypt=False):
    AES, pad, unpad, _ = crypto()
    if len(key) not in (16, 24, 32):
        raise ValueError('AES key must contain 16, 24, or 32 bytes')
    if decrypt and iv is None:
        raise ValueError('Decryption requires an IV')
    cipher = AES.new(key, AES.MODE_CBC, **({} if iv is None else {'iv': iv}))
    if decrypt:
        if not data or len(data) % 16:
            raise ValueError('Ciphertext must contain complete 16-byte blocks')
        try:
            return unpad(cipher.decrypt(data), 16), cipher.iv
        except ValueError as exc:
            raise ValueError('Invalid PKCS#7 padding; check key, IV, and ciphertext') from exc
    return cipher.encrypt(pad(data, 16)), cipher.iv


def flip_iv(token, offset, original, replacement):
    if len(token) < 32 or len(token) % 16:
        raise ValueError('Token must be a 16-byte IV followed by complete ciphertext blocks')
    if not original or len(original) != len(replacement):
        raise ValueError('Original and replacement must have equal, nonzero byte lengths')
    if offset < 0 or offset + len(original) > 16:
        raise ValueError('Replacement must fit within the first plaintext block')
    result = bytearray(token)
    for i, (before, after) in enumerate(zip(original, replacement)):
        result[offset + i] ^= before ^ after
    return bytes(result)


HASH_ALGORITHMS = ('sha256', 'sha512', 'sha3_256', 'blake2b', 'sha1', 'md5')


def hash_file(path, algorithm='sha256'):
    if algorithm not in HASH_ALGORITHMS:
        raise ValueError('Unsupported hash algorithm')
    digest = hashlib.new(algorithm)
    with Path(path).open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def integer(value):
    return int(value, 16) if value.lower().startswith('0x') else int(value, 10)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    rsa = commands.add_parser('rsa', help='Textbook RSA with supplied prime factors (no padding)')
    for name in ('p', 'q', 'e', 'ciphertext'):
        rsa.add_argument('--' + name, type=integer, required=True)
    for name in ('aes-encrypt', 'aes-decrypt'):
        aes = commands.add_parser(name, help='Offline AES-CBC with PKCS#7 padding')
        aes.add_argument('--input', type=Path, required=True)
        aes.add_argument('--key-file', type=Path, required=True, help='Raw binary AES key')
        aes.add_argument('--iv-hex', required=name == 'aes-decrypt')
    flip = commands.add_parser('flip-iv', help='Modify first-block plaintext in an IV-prefixed CBC token')
    flip.add_argument('--token', required=True)
    flip.add_argument('--encoding', choices=('hex', 'base64'), default='hex')
    flip.add_argument('--offset', type=int, required=True)
    flip.add_argument('--original-hex', required=True)
    flip.add_argument('--replacement-hex', required=True)
    hashing = commands.add_parser('hash', help='Hash a file or verify an expected digest')
    hashing.add_argument('--input', type=Path, required=True)
    hashing.add_argument('--algorithm', choices=HASH_ALGORITHMS, default='sha256')
    hashing.add_argument('--expected', help='Expected hexadecimal digest; mismatch exits with code 1')
    args = parser.parse_args(argv)
    try:
        if args.command == 'hash':
            digest = hash_file(args.input, args.algorithm)
            result = {'algorithm': args.algorithm, 'digest': digest}
            if args.expected is not None:
                expected = decode(args.expected, 'hex').hex()
                if len(expected) != len(digest):
                    raise ValueError('Expected digest has the wrong length for this algorithm')
                result['matches'] = hmac.compare_digest(digest, expected)
                print(json.dumps(result))
                return 0 if result['matches'] else 1
        elif args.command == 'rsa':
            result = {'plaintext_hex': rsa_decrypt(args.p, args.q, args.e, args.ciphertext).hex()}
        elif args.command.startswith('aes-'):
            data, iv = aes_cbc(args.input.read_bytes(), args.key_file.read_bytes(),
                               decode(args.iv_hex, 'hex') if args.iv_hex is not None else None,
                               args.command == 'aes-decrypt')
            result = {'data_base64': base64.b64encode(data).decode(), 'iv_hex': iv.hex()}
        else:
            token = flip_iv(decode(args.token, args.encoding), args.offset,
                            decode(args.original_hex, 'hex'), decode(args.replacement_hex, 'hex'))
            result = {'token': token.hex() if args.encoding == 'hex' else base64.b64encode(token).decode()}
        print(json.dumps(result))
        return 0
    except (ValueError, OSError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
