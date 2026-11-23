"""Unit tests for the cryptographic core (DiffieHellmanNode)."""

import base64

import pytest
from cryptography.fernet import InvalidToken

from dh_key_exchange import G, P, DiffieHellmanNode


def make_pair():
    """Return two nodes that completed the key exchange with each other."""
    alice = DiffieHellmanNode("A")
    bob = DiffieHellmanNode("B")
    alice.compute_shared_secret(bob.public_key)
    bob.compute_shared_secret(alice.public_key)
    return alice, bob


def test_public_key_matches_private_key():
    node = DiffieHellmanNode("N")
    assert 2 <= node.private_key <= P - 2
    assert node.public_key == pow(G, node.private_key, P)


def test_both_sides_derive_the_same_key():
    alice, bob = make_pair()
    token = alice.encrypt(b"hello")
    assert bob.decrypt(token) == b"hello"
    assert alice.decrypt(bob.encrypt(b"reply")) == b"reply"


def test_independent_sessions_use_different_keys():
    alice1, _ = make_pair()
    _, bob2 = make_pair()
    with pytest.raises(InvalidToken):
        bob2.decrypt(alice1.encrypt(b"hello"))


@pytest.mark.parametrize("bad_key", [-1, 0, 1, P - 1, P, P + 1])
def test_trivial_peer_public_keys_are_rejected(bad_key):
    node = DiffieHellmanNode("Test")
    with pytest.raises(ValueError, match="Invalid public key"):
        node.compute_shared_secret(bad_key)


def test_cipher_is_unusable_before_key_exchange():
    node = DiffieHellmanNode("Test")
    with pytest.raises(RuntimeError):
        node.encrypt(b"data")
    with pytest.raises(RuntimeError):
        node.decrypt(b"data")


def test_tampered_ciphertext_is_rejected():
    alice, bob = make_pair()
    raw = bytearray(base64.urlsafe_b64decode(alice.encrypt(b"Secret")))
    # Fernet token layout: version (1) | timestamp (8) | IV (16) | ciphertext | HMAC (32).
    # Flip one bit of the first ciphertext byte (index 25).
    raw[25] ^= 0x01
    tampered = base64.urlsafe_b64encode(bytes(raw))
    with pytest.raises(InvalidToken):
        bob.decrypt(tampered)


def test_empty_and_chunk_sized_payloads_roundtrip():
    alice, bob = make_pair()
    for payload in (b"", b"x", b"\x00" * 65536, bytes(range(256)) * 256):
        assert bob.decrypt(alice.encrypt(payload)) == payload
