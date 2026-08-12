"""SyncLink 插件的核心实现子包。

只包含纯逻辑（加密、图片编解码、KiraMac 混淆、常量协议定义），
不依赖 KiraAI 核心，便于独立测试与复用。插件主体见项目根目录的 ``main.py``。
"""
from . import constants as constants
from .crypto import KeyCipher, PasswordCipher
from .image_codec import ImageCodec
from .mac import MacObfuscator, kira_rand_mac

__all__ = [
    'constants',
    'PasswordCipher',
    'KeyCipher',
    'ImageCodec',
    'MacObfuscator',
    'kira_rand_mac',
]
