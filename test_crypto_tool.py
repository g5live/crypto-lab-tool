import unittest
import tempfile
import io
from pathlib import Path
from contextlib import redirect_stdout, redirect_stderr
from crypto_tool import aes_cbc, flip_iv, rsa_decrypt, main, hash_file


class CryptoTests(unittest.TestCase):
    def test_hash_and_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'message.bin'
            path.write_bytes(b'abc')
            expected = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
            self.assertEqual(hash_file(path), expected)
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(main(['hash', '--input', str(path), '--expected', expected.upper()]), 0)
                self.assertEqual(main(['hash', '--input', str(path), '--expected', '00' * 32]), 1)
                self.assertEqual(main(['hash', '--input', str(path), '--expected', 'wrong']), 2)
                self.assertEqual(main(['hash', '--input', str(path), '--expected', '00']), 2)
                self.assertEqual(main(['hash', '--input', str(path / 'missing')]), 2)

    def test_rsa_known_answer(self):
        self.assertEqual(rsa_decrypt(61, 53, 17, 2790), b'A')

    def test_rsa_invalid_parameters(self):
        for params in [(4, 53, 17, 2), (53, 53, 17, 2), (61, 53, 12, 2), (61, 53, 17, 3233)]:
            with self.assertRaises(ValueError):
                rsa_decrypt(*params)

    def test_aes_known_vector(self):
        key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
        iv = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
        plain = bytes.fromhex('6bc1bee22e409f96e93d7e117393172a')
        encrypted, _ = aes_cbc(plain, key, iv)
        self.assertEqual(encrypted[:16].hex(), '7649abac8119b246cee98e9b12e9197d')
        self.assertEqual(aes_cbc(encrypted, key, iv, True)[0], plain)

    def test_roundtrips(self):
        for plain in (b'', b'hello', bytes(range(256))):
            encrypted, iv = aes_cbc(plain, b'k' * 16)
            self.assertEqual(aes_cbc(encrypted, b'k' * 16, iv, True)[0], plain)

    def test_flip_decrypted_effect(self):
        encrypted, iv = aes_cbc(b'role=0;example', b'k' * 16)
        changed = flip_iv(iv + encrypted, 5, b'0', b'1')
        self.assertEqual(aes_cbc(changed[16:], b'k' * 16, changed[:16], True)[0], b'role=1;example')
        self.assertEqual(changed[16:], encrypted)

    def test_bad_inputs(self):
        for args in [(b'', 0, b'0', b'1'), (b'x' * 32, 16, b'0', b'1'), (b'x' * 32, 0, b'0', b'12')]:
            with self.assertRaises(ValueError):
                flip_iv(*args)
        with self.assertRaises(ValueError):
            aes_cbc(b'hi', b'short')
        with self.assertRaises(ValueError):
            aes_cbc(b'bad', b'k' * 16, b'i' * 16, True)
        with self.assertRaises(ValueError):
            aes_cbc(b'', b'k' * 16, None, True)


if __name__ == '__main__':
    unittest.main()
