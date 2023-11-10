from typing import Tuple
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher.PKCS1_OAEP import PKCS1OAEP_Cipher
from Crypto.Hash import SHA256
from Crypto.Hash.SHA256 import SHA256Hash
from Crypto.Signature import pkcs1_15
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme


class CryptoUtil:
    """
    Class with cryptographic functions
    """

    @staticmethod
    def generate_rsa_keys(key_len: int = 1024) -> Tuple[RsaKey, RsaKey]:
        """
        Generates an RSA key pair with the given key length

        :param key_len: the length of the keys
        :return: the key pair
        """
        private_rsa_key: RsaKey = RSA.generate(key_len)
        public_rsa_key: RsaKey = private_rsa_key.publickey()
        return private_rsa_key, public_rsa_key

    @staticmethod
    def encrypt_rsa(rsa_public_key: RsaKey, plaintext: str) -> bytes:
        """
        Encrypts a plaintext string with an RSA public key

        :param rsa_public_key: the public key to use for the encryption
        :param plaintext: the plaintext to encrypt
        :return: the encrypted data
        """
        plaintext_bytes: bytes = plaintext.encode("utf-8")
        cipher_rsa: PKCS1OAEP_Cipher = PKCS1_OAEP.new(rsa_public_key)
        ciphertext: bytes = cipher_rsa.encrypt(plaintext_bytes)
        return ciphertext

    @staticmethod
    def decrypt_rsa(rsa_private_key: RsaKey, ciphertext: bytes) -> bytes:
        """
        Decrypts a given ciphertext using a private RSA key

        :param rsa_private_key: the private RSA key
        :param ciphertext: the ciphertext to decrypt
        :return: the decrypted ciphertext
        """
        cipher_rsa: PKCS1OAEP_Cipher = PKCS1_OAEP.new(rsa_private_key)
        plaintext: bytes = cipher_rsa.decrypt(ciphertext)
        return plaintext

    @staticmethod
    def sign_message_rsa(rsa_private_key: RsaKey, message: str) -> bytes:
        """
        Signs a given plaintext message with an RSA private key

        :param rsa_private_key: the private key to use for the signature
        :param message: the message to sign
        :return: the signature
        """
        message_bytes = message.encode("utf-8")
        hash: SHA256 = SHA256.new(message_bytes)
        signer: PKCS115_SigScheme = pkcs1_15.new(rsa_key=rsa_private_key)
        signature: bytes = signer.sign(hash)
        return signature

    @staticmethod
    def verify_signature(message: str, signature: bytes, rsa_public_key: RsaKey) -> bool:
        """
        Verifies a given digital signature with a received message

        :param message: the received message
        :param signature: the digital signature
        :param rsa_public_key: the public RSA key of the signer
        :return: True if the signature is valid, False otherwise
        """
        message_bytes: bytes = message.encode("utf-8")
        message_hash: SHA256Hash = SHA256.new(data=message_bytes)
        signer: PKCS115_SigScheme = pkcs1_15.new(rsa_key=rsa_public_key)
        try:
            signer.verify(msg_hash=message_hash, signature=signature)
            return True
        except ValueError as _:
            return False
