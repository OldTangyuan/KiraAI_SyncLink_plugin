"""AES-256-GCM 加密工具。

包含两套加密，对应原实现中的两个阶段：
- ``PasswordCipher``：口令加密，密钥由 PBKDF2-HMAC-SHA256 派生，用于连接握手阶段。
- ``KeyCipher``：直接使用 32 字节密钥，用于连接建立后的通信阶段。
"""
import base64
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from . import constants as C


class PasswordCipher:
    """基于口令的 AES-256-GCM 加密（握手阶段：加密/解密真实 KiraMac）。"""

    def encrypt(self, plaintext: str, password: str) -> str:
        """用字符串口令加密，返回 Base64 密文（内含 salt 与 nonce）。"""
        salt = os.urandom(C.SALT_LEN)
        key = self._derive_key(password, salt)
        nonce = os.urandom(C.NONCE_LEN)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode('utf-8'), None)
        # 组合：salt + nonce + ciphertext（ciphertext 已含 GCM 认证标签）
        combined = salt + nonce + ciphertext
        return base64.b64encode(combined).decode('utf-8')

    def decrypt(self, encoded_data: str, password: str) -> str:
        """用字符串口令解密 Base64 密文，返回明文。"""
        combined = base64.b64decode(encoded_data)
        # 分离 salt、nonce、ciphertext
        salt = combined[:C.SALT_LEN]
        nonce = combined[C.SALT_LEN:C.SALT_LEN + C.NONCE_LEN]
        ciphertext = combined[C.SALT_LEN + C.NONCE_LEN:]
        key = self._derive_key(password, salt)
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
        return plaintext.decode('utf-8')

    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=C.AES_KEY_LEN,
            salt=salt,
            iterations=C.PBKDF2_ITERATIONS,
        )
        return kdf.derive(password.encode('utf-8'))


class KeyCipher:
    """基于 32 字节密钥的 AES-256-GCM 加密（通信阶段：``<sync>`` 消息）。"""

    @staticmethod
    def str_to_key(key_str: str) -> bytes:
        """将字符串转换为 32 字节密钥：取前 32 字节，不足用 ``\\0`` 补齐。"""
        key_bytes = key_str.encode('utf-8')
        if len(key_bytes) >= C.AES_KEY_LEN:
            return key_bytes[:C.AES_KEY_LEN]
        return key_bytes.ljust(C.AES_KEY_LEN, b'\0')

    def encrypt_data(self, plaintext: str, key: bytes) -> bytes:
        """加密字符串，返回 ``salt + nonce + ciphertext_with_tag`` 的字节串。"""
        if len(key) != C.AES_KEY_LEN:
            raise ValueError(f"密钥长度必须为{C.AES_KEY_LEN}字节，当前为 {len(key)} 字节")
        salt = os.urandom(C.SALT_LEN)
        nonce = os.urandom(C.NONCE_LEN)
        ciphertext_with_tag = AESGCM(key).encrypt(nonce, plaintext.encode('utf-8'), None)
        return salt + nonce + ciphertext_with_tag

    def decrypt_data(self, encrypted_data: bytes, key: bytes) -> str:
        """解密字节串，返回原始字符串。"""
        if len(key) != C.AES_KEY_LEN:
            raise ValueError(f"密钥长度必须为{C.AES_KEY_LEN}字节，当前为 {len(key)} 字节")
        # 分离 salt、nonce、ciphertext
        salt = encrypted_data[:C.SALT_LEN]
        nonce = encrypted_data[C.SALT_LEN:C.SALT_LEN + C.NONCE_LEN]
        ciphertext_with_tag = encrypted_data[C.SALT_LEN + C.NONCE_LEN:]
        plaintext_bytes = AESGCM(key).decrypt(nonce, ciphertext_with_tag, None)
        return plaintext_bytes.decode('utf-8')
