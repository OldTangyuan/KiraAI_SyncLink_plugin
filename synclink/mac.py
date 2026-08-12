"""KiraMac 的生成与混淆加密（仅用于连接握手阶段）。

注意：``MacObfuscator`` 的加密只是轻量混淆，可被轻易逆向，并非密码学安全；
它内部实际复用了 ``PasswordCipher``（AES）来完成加解密。
"""
import random
import re

from . import constants as C
from .crypto import PasswordCipher


def kira_rand_mac() -> str:
    """生成随机 KiraMac。

    这里的 MAC 地址并不标准，但作为 Kira 唯一标识符也够用了。
    """
    return C.KIRA_MAC_PREFIX + ':'.join(
        '%02x' % random.randint(0, 255) for _ in range(C.KIRA_MAC_BYTES)
    )


class MacObfuscator:
    """对 KiraMac 进行加密（``encrypt_mac``）与还原（``decrypt_mac``）。

    实现思路：先把每个字符转为 ASCII 码序号（空格分隔），再用随机字母数字
    作为口令做 AES 加密，并把该口令夹在密文的随机位置，最后拼上位置信息。
    """

    def __init__(self, cipher: PasswordCipher = None):
        self._cipher = cipher or PasswordCipher()

    def encrypt_mac(self, kira_mac: str) -> str:
        """对 KiraMac 进行加密，返回带位置信息与内嵌口令的密文。"""
        ord_mac = ' '.join(str(ord(char)) for char in kira_mac)
        length = random.randint(1, 5)
        position = random.randint(5, 10)
        key = self._random_alnum(length)
        return self._finish_ciphertext(ord_mac, key, position)

    def decrypt_mac(self, ciphertext: str) -> str:
        """解密 ``encrypt_mac`` 产生的密文，还原 KiraMac。

        按密文头部的位置信息精确切片剔除密钥，而不是用正则查找：
        原实现用 ``re.sub(key, ...)`` 删除密钥，当短密钥恰好也出现在密文
        前缀（base64 密文）中时会被误删，导致解密失败。
        """
        result = re.match(r'^(\d+)/(\d+)=', ciphertext)
        f_pos, l_pos = int(result.group(1)), int(result.group(2))
        body = re.sub(f'^{f_pos}/{l_pos}=', '', ciphertext)
        key = body[f_pos:l_pos]
        # 密钥位于 [f_pos, l_pos) 区间，直接切片剔除（修复误删缺陷）
        real_ciphertext = body[:f_pos] + body[l_pos:]
        plaintext = self._cipher.decrypt(real_ciphertext, key)
        return ''.join(chr(int(i)) for i in plaintext.split(' '))

    def _random_alnum(self, length: int) -> str:
        """生成指定长度的随机字母数字串。"""
        result = []
        for _ in range(length):
            category = random.randint(0, 2)
            if category == 0:           # 数字 '0'~'9' ASCII 48~57
                code = random.randint(48, 57)
            elif category == 1:         # 大写字母 'A'~'Z' ASCII 65~90
                code = random.randint(65, 90)
            else:                       # 小写字母 'a'~'z' ASCII 97~122
                code = random.randint(97, 122)
            result.append(chr(code))
        return ''.join(result)

    def _finish_ciphertext(self, ord_mac: str, key: str, position: int) -> str:
        """把加密结果与口令按 ``位置/长度=前缀+口令+后缀`` 组装。"""
        prime_ciphertext = self._cipher.encrypt(ord_mac, key)
        former_prime = prime_ciphertext[:position]
        latter_prime = prime_ciphertext[position:]
        return '%d/%d=%s%s%s' % (position, position + len(key), former_prime, key, latter_prime)
