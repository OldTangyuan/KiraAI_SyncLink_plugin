"""验证脚本：证明重构后的 ``synclink`` 子包与原逻辑行为一致。

验证方式（核心思路）：
- 对需要随机性的加密函数，把 ``os.urandom`` 替换为固定种子的确定性伪随机字节，
  再让新实现与原实现副本在同输入、同随机熵下运行，断言输出**逐字节一致**。
- 对纯函数（编解码、str_to_key、KiraMac 格式），直接断言结果一致。
- 对解密做「行为一致」断言：结果相同，或同样抛异常（覆盖原实现短密钥的既有缺陷）。

用法（项目根目录下）：
    .venv\\Scripts\\python -m tests.verify_synclink
"""
import os
import random
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Windows 控制台默认 GBK，统一改用 UTF-8 输出，避免中文 / emoji 触发 UnicodeEncodeError
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, 'reconfigure'):
        _stream.reconfigure(encoding='utf-8')

from tests.reference_original import (
    Encryptor as OrigEncryptor,
    ImageEncryptor as OrigImageEncryptor,
    kira_rand_mac as orig_kira_rand_mac,
)
from synclink.crypto import KeyCipher, PasswordCipher
from synclink.image_codec import ImageCodec
from synclink.mac import MacObfuscator, kira_rand_mac

# ---- 原实现副本（基准） ----
ORIG_ENC = OrigEncryptor()
ORIG_IMG = OrigImageEncryptor()

# ---- 重构后的新实现 ----
NEW_PWD = PasswordCipher()
NEW_KEY = KeyCipher()
NEW_MAC = MacObfuscator(NEW_PWD)
NEW_IMG = ImageCodec()

FAILURES: list = []


def check(name: str, cond: bool) -> None:
    print(f'  [{"OK" if cond else "FAIL"}] {name}')
    if not cond:
        FAILURES.append(name)


def det_urandom(seed: int):
    """构造确定性 ``os.urandom`` 替代函数（固定种子伪随机字节）。"""
    rng = random.Random(seed)
    return lambda n: bytes(rng.getrandbits(8) for _ in range(n))


@contextmanager
def det_entropy(seed: int):
    """临时用确定性熵替换 ``os.urandom``，结束后恢复。"""
    original = os.urandom
    os.urandom = det_urandom(seed)
    try:
        yield
    finally:
        os.urandom = original


# ---------------------------------------------------------------- 往返自测
def test_roundtrips():
    print('== 组件往返自测 ==')
    text, pwd = 'Kira 你好 🌐', 'p@ss'
    check('PasswordCipher 往返', NEW_PWD.decrypt(NEW_PWD.encrypt(text, pwd), pwd) == text)
    check('str_to_key 短串补齐', NEW_KEY.str_to_key('k') == b'k'.ljust(32, b'\0'))
    check('str_to_key 长串截断', len(NEW_KEY.str_to_key('x' * 100)) == 32)
    mac = kira_rand_mac()
    check('kira_rand_mac 格式', mac.startswith('kira:') and len(mac) == 22)


# ------------------------------------------------------ 与原实现逐字节对比
def test_password_cipher_identical():
    print('== PasswordCipher vs 原 Encryptor（逐字节兼容） ==')
    text, pwd = 'kira:aa:bb:cc:dd:ee:ff', 'SyncLink-密码'
    with det_entropy(1):
        new_ct = NEW_PWD.encrypt(text, pwd)
    with det_entropy(1):
        orig_ct = ORIG_ENC.encrypt_string(text, pwd)
    check('encrypt 输出逐字节一致', new_ct == orig_ct)
    check('原实现可解密新实现输出', ORIG_ENC.decrypt_string(new_ct, pwd) == text)
    check('新实现可解密原实现输出', NEW_PWD.decrypt(orig_ct, pwd) == text)


def test_mac_identical():
    print('== MacObfuscator vs 原 Encryptor（加密逐字节兼容） ==')
    mac_str = 'kira:12:34:56:78:9a:bc'
    for seed in (11, 22, 33, 44, 55):
        with det_entropy(seed):
            random.seed(seed)
            new_ct = NEW_MAC.encrypt_mac(mac_str)
        with det_entropy(seed):
            random.seed(seed)
            orig_ct = ORIG_ENC.encrypt_mac(mac_str)
        check(f'encrypt_mac 输出逐字节一致 (seed={seed})', new_ct == orig_ct)


def test_mac_decrypt_fix():
    print('== decrypt_mac 缺陷修复验证 ==')
    # 构造"密钥恰好出现在密文前缀"的合法密文——这正是触发原缺陷（re.sub 误删）的情形。
    # 加密输出 base64 密文中，1 字符密钥出现在前 10 位前缀的概率约 15%，故循环尝试即可命中。
    mac_str = 'kira:12:34:56:78:9a:bc'
    ord_mac = ' '.join(str(ord(c)) for c in mac_str)
    key, position = 'a', 10
    found = False
    for _ in range(30):
        prime = NEW_PWD.encrypt(ord_mac, key)
        if key in prime[:position]:
            found = True
            break
    check('构造出触发缺陷的合法密文', found)
    if found:
        body = prime[:position] + key + prime[position:]
        crafted = f'{position}/{position + len(key)}={body}'
        # 原实现：re.sub 误删前缀中的密钥 -> 解密失败
        try:
            ORIG_ENC.decrypt_mac(crafted)
            orig_fails = False
        except Exception:
            orig_fails = True
        check('原实现对此密文解密失败（缺陷复现）', orig_fails)
        # 新实现：按位置精确切片 -> 正确还原
        check('新实现正确还原该密文', NEW_MAC.decrypt_mac(crafted) == mac_str)

    # 真实随机往返：新实现必须全量成功
    random.seed(20260813)
    ok = True
    for _ in range(30):
        m = kira_rand_mac()
        if NEW_MAC.decrypt_mac(NEW_MAC.encrypt_mac(m)) != m:
            ok = False
            break
    check('新实现 30 次随机往返全量成功', ok)


def test_mac_generator_identical():
    print('== kira_rand_mac vs 原实现（同种子同结果） ==')
    random.seed(7)
    a = kira_rand_mac()
    random.seed(7)
    b = orig_kira_rand_mac()
    check('kira_rand_mac 输出一致', a == b)


def test_key_cipher_identical():
    print('== KeyCipher vs 原 ImageEncryptor（逐字节兼容） ==')
    text = 'kira:机密内容'
    key = NEW_KEY.str_to_key('kira:12:34:56:78:9a:bc')
    with det_entropy(2):
        new_data = NEW_KEY.encrypt_data(text, key)
    with det_entropy(2):
        orig_data = ORIG_IMG.encrypt_data(text, key)
    check('encrypt_data 输出逐字节一致', new_data == orig_data)
    check('交叉解密一致', ORIG_IMG.decrypt_data(new_data, key) == text
          and NEW_KEY.decrypt_data(orig_data, key) == text)
    check('str_to_key 输出一致', NEW_KEY.str_to_key('kira:12:34:56:78:9a:bc')
          == ORIG_IMG.str_to_key('kira:12:34:56:78:9a:bc'))


def test_image_codec_identical():
    print('== ImageCodec vs 原 ImageEncryptor（编解码兼容） ==')
    data = bytes(range(256)) * 4  # 1024 字节，覆盖全部字节值且末尾非零
    with tempfile.TemporaryDirectory() as d:
        p_new = str(Path(d) / 'new.png')
        p_orig = str(Path(d) / 'orig.png')
        NEW_IMG.bytes_to_image(data, p_new)
        ORIG_IMG.bytes_to_image(data, p_orig)
        check('image_to_bytes 解码结果一致',
              NEW_IMG.image_to_bytes(p_new) == ORIG_IMG.image_to_bytes(p_orig) == data)


# ------------------------------------------------------ 真实随机完整流程
def test_full_sync_flow():
    print('== 完整 <sync> 流程（真实随机熵） ==')
    key = NEW_KEY.str_to_key('kira:aa:bb:cc:dd:ee:ff')
    secret = '只有我俩能看到的悄悄话'
    with tempfile.TemporaryDirectory() as d:
        img_path = str(Path(d) / 'msg.png')
        # 发送方：加密 -> 图片
        ct = NEW_KEY.encrypt_data(f'kira:{secret}', key)
        NEW_IMG.bytes_to_image(ct, img_path)
        # 接收方：图片 -> 解密
        got = NEW_KEY.decrypt_data(NEW_IMG.image_to_bytes(img_path), key)
        check('sync 全流程往返一致', got == f'kira:{secret}')


def main():
    test_roundtrips()
    test_password_cipher_identical()
    test_mac_generator_identical()
    test_mac_identical()
    test_mac_decrypt_fix()
    test_key_cipher_identical()
    test_image_codec_identical()
    test_full_sync_flow()

    if FAILURES:
        print(f'\n❌ {len(FAILURES)} 项未通过：{FAILURES}')
        sys.exit(1)
    print('\n全部验证通过 ✅')


if __name__ == '__main__':
    main()
