"""Backend contract tests: shared interop vector, RFC 8439 AEAD vector,
tamper rejection, enrollment proof-of-possession, atomic replay claims.

Run: python3 -m unittest test_hce_backend.py -v  (stdlib only)
The vector constants MUST match src/HceProtocol.h TestVector.
"""
import unittest

from hce_verify import (NonceStore, aead_decrypt, aead_encrypt, enroll,
                        unwrap_key, verify_proof)

class Vector(unittest.TestCase):
    CRED = "PLS-K3Y7V3CT0R5Z"
    KEY = bytes(range(32))
    NONCE_HEX = "000102030405060708090a0b0c0d0e0f"
    MAC_HEX = "70f32d7b458139d8f5f522a7314c31205eca50619a5d26dc466d7d5b60aab154"
    SECRET = b"test-secret-000000000000000001"
    KEY_NONCE_HEX = "000102030405060708090a0b"
    WRAPPED_HEX = ("000102030405060708090a0b"
                   "d525e39925f68721c72478ce0d25a8078efb99ee6974f2cd8dad8c872882f"
                   "aa4dfcb78880fbc7ee165be05086565530e")

    def test_vector_mac_verifies(self):
        self.assertTrue(verify_proof(self.CRED, self.NONCE_HEX, self.MAC_HEX, self.KEY))

    def test_vector_rejects_wrong_key_mac_nonce(self):
        bad = bytearray(self.KEY)
        bad[0] ^= 1
        self.assertFalse(verify_proof(self.CRED, self.NONCE_HEX, self.MAC_HEX, bytes(bad)))
        flipped = ("a" if self.MAC_HEX[0] != "a" else "b") + self.MAC_HEX[1:]
        self.assertFalse(verify_proof(self.CRED, self.NONCE_HEX, flipped, self.KEY))
        self.assertFalse(verify_proof(self.CRED, "ff" * 16, self.MAC_HEX, self.KEY))
        self.assertFalse(verify_proof(self.CRED, "zzzz", self.MAC_HEX, self.KEY))
        self.assertFalse(verify_proof("", self.NONCE_HEX, self.MAC_HEX, self.KEY))

    def test_vector_wraps_and_unwraps(self):
        cand = unwrap_key(self.SECRET, self.CRED, self.KEY_NONCE_HEX, self.WRAPPED_HEX)
        self.assertEqual(cand, self.KEY)

    def test_unwrap_fails_closed(self):
        self.assertIsNone(unwrap_key(b"wrong-secret", self.CRED, self.KEY_NONCE_HEX,
                                     self.WRAPPED_HEX))
        bad = ("a" if self.WRAPPED_HEX[30] != "a" else "b") + self.WRAPPED_HEX[31:]
        self.assertIsNone(unwrap_key(self.SECRET, self.CRED, self.KEY_NONCE_HEX, bad))
        self.assertIsNone(unwrap_key(self.SECRET, self.CRED, self.KEY_NONCE_HEX, "zzzz"))
        self.assertIsNone(unwrap_key(self.SECRET, self.CRED, "ff" * 12, self.WRAPPED_HEX))


class Rfc8439(unittest.TestCase):
    def test_aead_section_2_8_2(self):
        key = bytes(0x80 + i for i in range(32))
        nonce = bytes([0x07, 0, 0, 0, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47])
        aad = bytes([0x50, 0x51, 0x52, 0x53, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7])
        pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you "
              b"only one tip for the future, sunscreen would be it.")
        ct, tag = aead_encrypt(key, nonce, aad, pt)
        self.assertEqual(tag.hex(), "1ae10b594f09e26a7e902ecbd0600691")
        self.assertTrue(ct.hex().startswith("d31a8d34648e60db"))
        self.assertEqual(aead_decrypt(key, nonce, aad, ct, tag), pt)
        bad = bytearray(ct)
        bad[0] ^= 1
        self.assertIsNone(aead_decrypt(key, nonce, aad, bytes(bad), tag))


class Enrollment(unittest.TestCase):
    def test_enroll_stores_under_proof_of_possession(self):
        store = {}
        key = enroll(Vector.SECRET, Vector.CRED, Vector.NONCE_HEX, Vector.MAC_HEX,
                     Vector.KEY_NONCE_HEX, Vector.WRAPPED_HEX, store)
        self.assertEqual(key, Vector.KEY)
        self.assertEqual(store[Vector.CRED], Vector.KEY)

    def test_enroll_rejects_mismatched_proof(self):
        store = {}
        with self.assertRaises(ValueError):
            enroll(Vector.SECRET, "PLS-SOMEONE-ELSE", Vector.NONCE_HEX, Vector.MAC_HEX,
                   Vector.KEY_NONCE_HEX, Vector.WRAPPED_HEX, store)
        self.assertEqual(store, {})

    def test_enroll_rejects_wrong_secret(self):
        with self.assertRaises(ValueError):
            enroll(b"wrong-secret", Vector.CRED, Vector.NONCE_HEX, Vector.MAC_HEX,
                   Vector.KEY_NONCE_HEX, Vector.WRAPPED_HEX, {})


class Replay(unittest.TestCase):
    def test_nonce_claim_is_single_use(self):
        store = NonceStore()
        self.assertTrue(store.claim(Vector.CRED, Vector.NONCE_HEX))
        self.assertFalse(store.claim(Vector.CRED, Vector.NONCE_HEX))  # replay
        self.assertTrue(store.claim(Vector.CRED, "ff" * 16))  # fresh nonce ok
        self.assertTrue(store.claim("OTHER-CRED", Vector.NONCE_HEX))  # per-credential scope

    def test_verify_alone_accepts_twice(self):
        # verify_proof is validity-only; the store is what rejects replays.
        self.assertTrue(verify_proof(Vector.CRED, Vector.NONCE_HEX, Vector.MAC_HEX, Vector.KEY))
        self.assertTrue(verify_proof(Vector.CRED, Vector.NONCE_HEX, Vector.MAC_HEX, Vector.KEY))


if __name__ == "__main__":
    unittest.main()
