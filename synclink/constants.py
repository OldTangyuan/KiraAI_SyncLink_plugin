"""SyncLink 插件的常量与协议定义：加密参数、超时、协议标签正则、提示文案等。

此模块不依赖 KiraAI 核心，可被独立导入与测试。
"""
import re

# ------------------------- 加密参数 -------------------------
PBKDF2_ITERATIONS = 600_000   # PBKDF2 迭代次数，可依性能调整
SALT_LEN = 16                 # 盐长度（字节）
NONCE_LEN = 12                # AES-GCM nonce 长度（字节）
AES_KEY_LEN = 32              # AES-256 密钥长度（字节）

# ------------------------- 超时（秒） -------------------------
HANDSHAKE_TIMEOUT = 300       # 握手阶段（connect / back_connect）超时
LINK_TIMEOUT = 1800           # 连接建立后的活动超时

# ------------------------- KiraMac -------------------------
KIRA_MAC_PREFIX = 'kira:'
KIRA_MAC_BYTES = 6            # KiraMac 随机字节数

# ------------------------- 协议标签正则 -------------------------
# 注意：以下正则与原实现保持一致（`(.*)` 为贪婪匹配）
FILTER_PATTERN = re.compile(
    r'<CNCT>(.*)</CNCT>|<BCNCT>(.*)</BCNCT>|<FCNCT>(.*)</FCNCT>|<SYNC>(.*)</SYNC>',
    re.S,
)

CNCT_PATTERN = re.compile(r'^<CNCT>(.*)</CNCT>$')
BCNCT_PATTERN = re.compile(r'^<BCNCT>(.*)</BCNCT>$')
FCNCT_PATTERN = re.compile(r'^<FCNCT>(.*)</FCNCT>$')
SYNC_PATTERN = re.compile(r'^<SYNC>(.*)</SYNC>$')

KIRA_PREFIX_PATTERN = re.compile(r'^kira:')


# ------------------------- 提示 / 通知文案 -------------------------
def notice_timeout() -> str:
    """连接超时被强制重置的系统提示"""
    return '[System: 连接超时，你被系统强制取消并重置（你不需要自己再取消一次）]'


def notice_connect_request(sender_name: str) -> str:
    """收到连接邀请时询问是否接受的系统提示"""
    return f'[System: “{sender_name}”发起了连接请求，如果同意连接请使用<back_connect>Tag]'


def notice_link_established(sender_name: str) -> str:
    """连接建立成功的提示"""
    return f'[SYNCLINK: 已成功建立与{sender_name}的连接，可使用<sync>Tag进行加密通信]'


def notice_encrypted_message(sender_name: str, real_text: str) -> str:
    """收到加密消息时转告明文内容的提示"""
    return f'[SYNCLINK: “{sender_name}”发送了加密消息“{real_text}”，如需回复请使用<sync>Tag]'


# 连接建立后注入系统提示词的内容，nickname 为对方昵称
# 注意使用 %s 占位，与原实现保持一致（避免 .format 对昵称中花括号敏感）
SYNCLINK_PROMPT = (
    '[SYNCLINK: 你已成功与“%s”进行连接，可以使用<sync>Tag进行加密通信，'
    '其中加密的内容只有你和对方可以看到，其他人只能看到乱码，'
    '所以请放心在里面输出一切内容]'
)


# ------------------------- 数据文件 -------------------------
def default_data(kira_mac: str) -> dict:
    """首次加载时生成的 data.json 结构"""
    return {'KiraMac': kira_mac, 'CachedKiraMac': []}
