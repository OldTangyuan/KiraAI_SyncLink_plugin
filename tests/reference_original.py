"""原逻辑基准副本（仅供回归验证，不要修改）。

这是重构前 ``main.py`` 中 ``kira_rand_mac`` / ``Encryptor`` / ``ImageEncryptor``
的**逐字副本**（仅去掉对 KiraAI ``core.*`` 的依赖），用于验证重构后的
``synclink`` 子包与原实现行为逐字节兼容。

⚠️ 本文件固定为「重构前」的样子，**不得改动**，否则会失去回归基准的意义。
"""
import base64
import os
import random
import re

import numpy as np
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import Image as pilimage


def kira_rand_mac():
    """这里的MAC地址并不标准，但作为Kira唯一标识符也够用了"""
    return 'kira:%s' % ':'.join('%02x' % random.randint(0, 255) for _ in range(6))


class Encryptor:
    """对数据进行加密和解密"""
    # 配置参数
    PBKDF2_ITERATIONS = 600_000   # 推荐值，可根据性能调整
    SALT_LEN = 16
    NONCE_LEN = 12

    def encrypt_mac(self, kira_mac):
        """对KiraMac进行加密"""
        ord_mac = ' '.join([str(ord(char)) for char in kira_mac])
        length = random.randint(1, 5)
        position = random.randint(5, 10)
        key = self.random_alnum(length)
        ciphertext = self.finish_ciphertext(ord_mac, key, position)
        return ciphertext

    def decrypt_mac(self, ciphertext: str):
        """对密文进行解密"""
        result = re.match(r'^(\d+)/(\d+)=', ciphertext)
        f_pos, l_pos = int(result.group(1)), int(result.group(2))
        ciphertext = re.sub(f'^{f_pos}/{l_pos}=', '', ciphertext)
        key = ciphertext[f_pos:l_pos]
        real_ciphertext = re.sub(f'{key}', '', ciphertext, count=1)
        plaintext = self.decrypt_string(real_ciphertext, key)
        plaint_list = plaintext.split(' ')
        kira_mac = ''.join([chr(int(i)) for i in plaint_list])
        return kira_mac

    def random_alnum(self, length: int):
        result = []
        for _ in range(length):
            # 随机选择类别：0-数字，1-大写字母，2-小写字母
            category = random.randint(0, 2)
            if category == 0:           # 数字 '0'~'9' ASCII 48~57
                code = random.randint(48, 57)
            elif category == 1:         # 大写字母 'A'~'Z' ASCII 65~90
                code = random.randint(65, 90)
            else:                       # 小写字母 'a'~'z' ASCII 97~122
                code = random.randint(97, 122)
            result.append(chr(code))

        return ''.join(result)

    def finish_ciphertext(self, ord_mac, key, position):
        prime_ciphertext = self.encrypt_string(ord_mac, key)
        former_prime = prime_ciphertext[:position]
        latter_prime = prime_ciphertext[position:]
        finished_ciphertext = '%d/%d=%s%s%s' % (position, position + len(key), former_prime, key, latter_prime)
        return finished_ciphertext

    def encrypt_string(self, plaintext: str, password: str) -> str:
        """用字符串密码加密，返回 Base64 密文"""
        # 生成随机盐
        salt = os.urandom(self.SALT_LEN)
        # 派生 32 字节 AES 密钥
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.PBKDF2_ITERATIONS,
        )
        key = kdf.derive(password.encode('utf-8'))

        # 生成随机 nonce
        nonce = os.urandom(self.NONCE_LEN)
        aesgcm = AESGCM(key)

        # 加密（GCM 自动附加认证标签）
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)

        # 组合：salt + nonce + ciphertext（ciphertext 已包含 tag）
        combined = salt + nonce + ciphertext
        return base64.b64encode(combined).decode('utf-8')

    def decrypt_string(self, encoded_data: str, password: str) -> str:
        """用字符串密码解密 Base64 密文"""
        combined = base64.b64decode(encoded_data)

        # 分离 salt, nonce, ciphertext
        salt = combined[:self.SALT_LEN]
        nonce = combined[self.SALT_LEN:self.SALT_LEN + self.NONCE_LEN]
        ciphertext = combined[self.SALT_LEN + self.NONCE_LEN:]

        # 重新派生密钥
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.PBKDF2_ITERATIONS,
        )
        key = kdf.derive(password.encode('utf-8'))

        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode('utf-8')


class ImageEncryptor:
    """连接完成后的加密通信"""

    def encrypt_data(self, plaintext: str, key: bytes) -> bytes:
        """
        使用 AES-256-GCM 加密字符串
        返回格式: [32 字节的盐 (salt)] + [12 字节的 nonce] + [密文+16字节的认证标签]
        """
        # 1. 检查密钥长度（必须是 32 字节）
        if len(key) != 32:
            raise ValueError(f"密钥长度必须为32字节，当前为 {len(key)} 字节")

        # 2. 生成一个随机的 16 字节盐（salt）和 12 字节 nonce
        salt = os.urandom(16)
        nonce = os.urandom(12)

        # 3. 加密数据
        aesgcm = AESGCM(key)
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)

        # 4. 返回 salt + nonce + ciphertext_with_tag
        return salt + nonce + ciphertext_with_tag

    def decrypt_data(self, encrypted_data: bytes, key: bytes) -> str:
        """
        解密数据，返回原始字符串
        """
        if len(key) != 32:
            raise ValueError(f"密钥长度必须为32字节，当前为 {len(key)} 字节")

        # 1. 分离数据
        salt = encrypted_data[:16]
        nonce = encrypted_data[16:28]  # 12 字节
        ciphertext_with_tag = encrypted_data[28:]

        # 2. 解密并验证
        aesgcm = AESGCM(key)
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, None)

        # 3. 返回字符串
        return plaintext_bytes.decode('utf-8')

    # ------------------------- 图像编码/解码 -------------------------
    def bytes_to_image(self, data: bytes, output_path: str, width=None):
        """
        将二进制数据编码为 PNG 图像
        使用 PngBin 方案：直接将数据写入 RGB 像素通道
        """
        if not data:
            raise ValueError("没有数据可编码")

        # 1. 计算图像尺寸
        total_pixels_needed = (len(data) + 2) // 3  # 向上取整，每个像素存 3 字节 (RGB)
        if width is None:
            width = int(total_pixels_needed ** 0.5) + 1

        height = (total_pixels_needed + width - 1) // width

        # 2. 创建像素数组
        pixels = np.zeros((height, width, 3), dtype=np.uint8)
        data_index = 0
        data_len = len(data)

        # 填充 RGB 通道
        for y in range(height):
            for x in range(width):
                for c in range(3):  # R, G, B
                    if data_index < data_len:
                        pixels[y, x, c] = data[data_index]
                        data_index += 1
                    else:
                        pixels[y, x, c] = 0

        # 3. 保存为 PNG
        img = pilimage.fromarray(pixels, 'RGB')
        img.save(output_path, 'PNG')
        print(f"图像已保存至: {output_path} (尺寸: {width}x{height})")

        return width, height

    def image_to_bytes(self, image_path: str) -> bytes:
        """
        从 PNG 图像中解码出原始二进制数据
        """
        # 1. 读取图像
        img = pilimage.open(image_path)
        pixels = np.array(img)
        height, width, _ = pixels.shape

        # 2. 提取 RGB 通道数据
        data = bytearray()
        for y in range(height):
            for x in range(width):
                for c in range(3):  # R, G, B
                    data.append(pixels[y, x, c])

        # 3. 找到数据的有效结尾（最后一个非零字节）
        # 注意：如果原始数据正好被 0 填充，这种方法会截断末尾的 0
        # 对于加密数据（随机字节），末尾几乎不可能是 0，所以安全
        # 更严谨的做法是在数据前加上长度头，但为了简化，这里假设加密数据末尾不会是 0
        last_non_zero = len(data) - 1
        while last_non_zero >= 0 and data[last_non_zero] == 0:
            last_non_zero -= 1

        return bytes(data[:last_non_zero + 1])

    # ------------------------- 完整流程 -------------------------
    def encrypt_text_to_image(self, plaintext: str, key: bytes, image_path: str):
        """加密文本并保存为图像"""
        encrypted_data = self.encrypt_data(plaintext, key)
        self.bytes_to_image(encrypted_data, image_path)
        return encrypted_data

    def decrypt_image_to_text(self, image_path: str, key: bytes) -> str:
        """从图像中解密文本"""
        encrypted_data = self.image_to_bytes(image_path)
        plaintext = self.decrypt_data(encrypted_data, key)
        return plaintext

    def str_to_key(self, key_str: str) -> bytes:
        """将字符串转换为 32 字节密钥"""
        key_bytes = key_str.encode('utf-8')
        if len(key_bytes) >= 32:
            return key_bytes[:32]
        else:
            return key_bytes.ljust(32, b'\0')
