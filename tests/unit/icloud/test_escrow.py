"""Offline tests for escrow bottle recovery + voucher (synthetic bottle, no Apple calls).

Builds an OTBottle the way Apple's escrow does (entropy -> HKDF keys -> AES-GCM-wrapped
OTInternalBottle), then recovers the peer keys back and signs a voucher. Proves the bottle
crypto + voucher composition; the live escrowproxy SRP (which yields the entropy) is separate
and gated.

Run: .venv/bin/python -m unittest tests.test_escrow
"""

import os
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature

from passwords_app.icloud.octagon import keys as ok
from passwords_app.icloud.escrow import bottle as escrow
from passwords_app.icloud.proto.codec import Writer, decode_fields, first, first_str


def _spki(priv):
    return priv.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _build_bottle(entropy, adsid, peer_id, signing_peer, encryption_peer):
    # OTInternalBottle{ signingKey(3), encryptionKey(4) } of OTPrivateKey{keyType(1),keyData(2)}
    def otpriv(peer):
        return Writer().uint64(1, 1).bytes(2, peer.private_x963()).finish()
    internal = (Writer().message(3, otpriv(signing_peer))
                .message(4, otpriv(encryption_peer)).finish())

    sym = escrow.derive_symmetric_key(entropy, adsid)
    iv = os.urandom(32)
    blob = AESGCM(sym).encrypt(iv, internal, None)
    ct, tag = blob[:-16], blob[-16:]

    return escrow.OTBottle(
        escrowed_signing_key=_spki(escrow.derive_ec_private_key(
            entropy, adsid, escrow._HKDF_INFO_SIGNING)),
        escrowed_encryption_key=_spki(escrow.derive_ec_private_key(
            entropy, adsid, escrow._HKDF_INFO_ENCRYPTION)),
        ct=ct, auth_code=tag, iv=iv, peer_id=peer_id, bottle_id="bottle-uuid")


class BottleRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.entropy = os.urandom(72)
        self.adsid = "001385-10-AAAA"
        self.signing = ok.generate_peer_key()
        self.encryption = ok.generate_peer_key()
        self.bottle = _build_bottle(self.entropy, self.adsid, "SHA256:oldpeer",
                                    self.signing, self.encryption)

    def test_recovers_exact_keys(self):
        rec = escrow.recover_identity(self.bottle, self.entropy, self.adsid)
        self.assertEqual(rec.peer_id, "SHA256:oldpeer")
        self.assertEqual(rec.signing_key.private_x963(), self.signing.private_x963())
        self.assertEqual(rec.encryption_key.private_x963(), self.encryption.private_x963())

    def test_bottle_round_trips_through_parse(self):
        parsed = escrow.OTBottle.parse(self.bottle.encode())
        rec = escrow.recover_identity(parsed, self.entropy, self.adsid)
        self.assertEqual(rec.signing_key.private_x963(), self.signing.private_x963())

    def test_wrong_entropy_rejected_by_verify(self):
        with self.assertRaises(escrow.EscrowError):
            escrow.recover_identity(self.bottle, os.urandom(72), self.adsid)

    def test_wrong_adsid_rejected(self):
        with self.assertRaises(escrow.EscrowError):
            escrow.recover_identity(self.bottle, self.entropy, "different-adsid")


class VoucherTests(unittest.TestCase):
    def test_voucher_signed_by_recovered_key(self):
        entropy = os.urandom(72)
        adsid = "001385-10-BBBB"
        signing = ok.generate_peer_key()
        encryption = ok.generate_peer_key()
        bottle = _build_bottle(entropy, adsid, "SHA256:sponsor", signing, encryption)
        rec = escrow.recover_identity(bottle, entropy, adsid)

        voucher = rec.make_voucher("SHA256:newpeer")
        v = decode_fields(voucher.info)
        self.assertEqual(first_str(v, 2), "SHA256:newpeer")   # beneficiary
        self.assertEqual(first_str(v, 3), "SHA256:sponsor")   # sponsor
        self.assertEqual(first(v, 1), 1)                       # reason
        # signature verifies under the recovered signing key, over the TPPB.Voucher prefix
        pub = signing.private_key.public_key()
        pub.verify(voucher.sig, b"TPPB.Voucher" + voucher.info, ec.ECDSA(hashes.SHA384()))
        with self.assertRaises(InvalidSignature):
            pub.verify(voucher.sig, voucher.info, ec.ECDSA(hashes.SHA384()))


if __name__ == "__main__":
    unittest.main()
