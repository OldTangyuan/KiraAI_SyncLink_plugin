from core.plugin import BasePlugin, PluginContext, get_logger
from core.plugin import on, Priority
from core.plugin import register
from core.chat import KiraMessageEvent, MessageChain, KiraMessageBatchEvent
from core.chat.message_elements import Text, At, Image
from core.provider import LLMRequest
from core.prompt_manager import Prompt

import random
import asyncio
import json
from pathlib import Path
import re
import os
import base64
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from PIL import Image as pilimage
import numpy as np
logger = get_logger('plugin-SyncLink', 'orange')
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
    
    def decrypt_mac(self, ciphertext:str):
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
        finished_ciphertext = '%d/%d=%s%s%s' % (position, position+len(key), former_prime, key, latter_prime)
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
        nonce = combined[self.SALT_LEN:self.SALT_LEN+self.NONCE_LEN]
        ciphertext = combined[self.SALT_LEN+self.NONCE_LEN:]
        
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
    def bytes_to_image(self, data: bytes, output_path: str, width: Optional[int] = None):
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

class SyncLink(BasePlugin):
    def __init__(self, ctx: PluginContext, cfg: dict):
        super().__init__(ctx, cfg)
        self.data_dir: Path = None
        self.data_file: Path = None

        self.kira_mac = None
        self.fake_kira_mac = None
        self.plaintext_kira_mac = None
        self.real_target_kira_mac = None

        self.encryptor = Encryptor()
        self.imgencryptor = ImageEncryptor()
        self._task: asyncio.Task = None

        # status
        self.try_to_connect = False
        self.back_to_connect = False
        self.connecting = False
        self.connect_data = None

    async def initialize(self):
        """插件加载时调用，在此初始化资源、注册事件等"""
        self.data_dir = self.ctx.get_plugin_data_dir()
        self.data_file = self.data_dir / "data.json"
        self.image_file = (self.data_dir / "encrypted_message.png").__str__()
        if not self.data_file.exists():
            kira_mac = kira_rand_mac()
            data = {'KiraMac': kira_mac, 'CachedKiraMac': []}
            self.data_file.write_text(json.dumps(data), encoding="utf-8")
            self.kira_mac = kira_mac
        else:
            self.kira_mac = json.loads(self.data_file.read_text()).get('KiraMac')
        logger.info('SyncLink插件加载完成！')

    async def terminate(self):
        """插件卸载时调用，在此释放资源、取消任务等"""
        await self.reset_link()
        await self.cancel_task()

    async def cancel_task(self):
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def start_task(self, t: int):
        await self.cancel_task()
        self._task = asyncio.create_task(self._background_loop(t))
        if self._task:
            try:
                await asyncio.sleep(0)
            except asyncio.CancelledError:
                pass

    async def _background_loop(self, t: int):
        await asyncio.sleep(t)  # 每t s执行一次
        try:
            await self.reset_link()
            await self.send_notice(self.session_id, '[System: 连接超时，你被系统强制取消并重置（你不需要自己再取消一次）]')
            logger.warning('连接超时，自动中断')
        except asyncio.CancelledError:
            return
        except Exception as e:
            logger.error(f"后台任务异常: {e}")

    async def reset_link(self):
        """重置连接"""
        await self.cancel_task()
        self.try_to_connect = False
        self.back_to_connect = False
        self.connecting = False
        self.connect_data = None

        self.fake_kira_mac = None
        self.plaintext_kira_mac = None
        self.real_target_kira_mac = None
        logger.info('连接已重置')

    async def cache_kira_mac(self, kira_mac, nickname, qq_id):
        """缓存连接到的KiraMac"""
        self.data_dir = self.ctx.get_plugin_data_dir()
        self.data_file = self.data_dir / "data.json"
        if self.data_file.exists():
            cached_data = {'KiraMac': kira_mac, 'nickname': nickname, 'qq_id': qq_id}
            self.connect_data = cached_data
            data = json.loads(self.data_file.read_text())
            if kira_mac in [dict_.get('KiraMac') for dict_ in data['CachedKiraMac']]:
                return
            data['CachedKiraMac'].append(cached_data)
            self.data_file.write_text(json.dumps(data), encoding="utf-8")

    async def send_notice(self, session_id: str, content: str):
        chain = MessageChain([Text(content)])
        await self.ctx.publish_notice(
            session=session_id,
            chain=chain,
            is_mentioned=True
        )

    async def send_to_group(self, ada_name, group_id, content):
        chain = MessageChain([Text(content)])
        await self.ctx.adapter_mgr.get_adapter(ada_name).send_group_message(
            group_id=group_id,
            send_message_obj=chain
        )

    @on.llm_request()
    async def inject_prompt(self, event, req: LLMRequest, tag_set, *args, **kwargs):
        # # 方式一：向已有 section 追加字符串内容
        # for p in req.system_prompt:
        #     if p.name == "tools":
        #         p.content += "\n你可以使用 my_tool 工具来..."
        #         break

        # 方式二：追加一个新的 Prompt 对象
        # name 为该 Prompt 的名称，source 为来源，建议设置为插件 ID
        if self.connecting:
            req.system_prompt.append(Prompt(
                content="[SYNCLINK: 你已成功与“%s”进行连接，可以使用<sync>Tag进行加密通信，其中加密的内容只有你和对方可以看到，其他人只能看到乱码，所以请放心在里面输出一切内容]" % self.connect_data.get('nickname', ''),
                name="sync_link_context",
                source="SyncLink",
            ))

    @on.im_batch_message()
    async def filter_llm_request(self, event: KiraMessageBatchEvent, *args, **kwargs):
        """
        在 LLM 请求发出前，对用户消息和助手历史消息进行内容替换
        """
        for msg in event.messages:
            original = msg.message_str
            filtered = re.sub(r'<CNCT>(.*)</CNCT>|<BCNCT>(.*)</BCNCT>|<FCNCT>(.*)</FCNCT>|<SYNC>(.*)</SYNC>', '', original, flags=re.S)
            if original != filtered:
                msg.message_str = filtered

    @on.im_message(priority=Priority.HIGH)
    async def on_message(self, event: KiraMessageEvent, *args, **kwargs):
        # 方式一：message_repr，所有元素的 repr 拼接（立即可用）
        # text = event.message_repr

        # 方式二：从 chain 中提取纯文本（只取 Text 元素）
        text = "".join(ele.text for ele in event.message.chain if isinstance(ele, Text))
        at = "".join(ele.pid for ele in event.message.chain if isinstance(ele, At))
        image = [ele for ele in event.message.chain if isinstance(ele, Image)]
        real_text = ''
        target_kira_mac=''
        receive_real_target_kira_mac=''
        real_target_kira_mac=''
        image_type=''
        if event.is_mentioned:
            self.session_id = event.session.__str__()
        if (target_kira_mac:= re.match(r'^<CNCT>(.*)</CNCT>$', text.strip())) and not self.connecting and not self.try_to_connect:
            target_kira_mac = target_kira_mac.group(1)
            self.plaintext_kira_mac = self.encryptor.decrypt_mac(target_kira_mac)
        elif (receive_real_target_kira_mac:= re.match(r'^<BCNCT>(.*)</BCNCT>$', text.strip())) and not self.connecting and self.try_to_connect:
            receive_real_target_kira_mac = receive_real_target_kira_mac.group(1)
            self.real_target_kira_mac = self.encryptor.decrypt_string(receive_real_target_kira_mac, self.fake_kira_mac)
        elif (real_target_kira_mac:= re.match(r'^<FCNCT>(.*)</FCNCT>$', text.strip())) and not self.connecting and self.back_to_connect:
            real_target_kira_mac = real_target_kira_mac.group(1)
            self.real_target_kira_mac = self.encryptor.decrypt_string(real_target_kira_mac, self.kira_mac)
        elif (image_type:= re.match(r'^<SYNC>(.*)</SYNC>$', text.strip())) and self.connecting and image:
            path = await image[0].to_path()
            try:
                real_text = self.imgencryptor.decrypt_image_to_text(path, self.imgencryptor.str_to_key(self.kira_mac))
            except:
                real_text = ''
            
        if self.plaintext_kira_mac and "kira:" in self.plaintext_kira_mac and at == event.message.self_id and target_kira_mac:
            event.discard(True)
            session_id = event.session.__str__()
            sender_name = event.message.sender.nickname
            await self.send_notice(session_id, f'[System: “{sender_name}”发起了连接请求，如果同意连接请使用<back_connect>Tag]')
        elif self.real_target_kira_mac and "kira:" in self.real_target_kira_mac and receive_real_target_kira_mac:
            await self.cancel_task()
            self.try_to_connect = False
            self.connecting = True
            await self.start_task(1800)
            await self.cache_kira_mac(self.real_target_kira_mac, event.message.sender.nickname, event.message.sender.user_id)
            ada_name = event.session.adapter_name
            group_id = event.message.group.group_id
            self_kira_mac = self.encryptor.encrypt_string(self.kira_mac, self.real_target_kira_mac)
            await self.send_to_group(ada_name, group_id, f'<FCNCT>{self_kira_mac}</FCNCT>')
            session_id = event.session.__str__()
            sender_name = event.message.sender.nickname
            await self.send_notice(session_id, f'[SYNCLINK: 已成功建立与{sender_name}的连接，可使用<sync>Tag进行加密通信]')
        elif self.real_target_kira_mac and "kira:" in self.real_target_kira_mac and real_target_kira_mac:
            await self.cancel_task()
            self.back_to_connect = False
            self.connecting = True
            await self.start_task(1800)
            await self.cache_kira_mac(self.real_target_kira_mac, event.message.sender.nickname, event.message.sender.user_id)
        elif image_type and image and 'kira:' in real_text:
            await self.cancel_task()
            event.discard(True)
            session_id = event.session.__str__()
            sender_name = event.message.sender.nickname
            real_text = re.sub(r'^kira:', '', real_text, count=1, flags=re.S)
            await self.start_task(1800)
            await self.send_notice(session_id, f'[SYNCLINK: “{sender_name}”发送了加密消息“{real_text}”，如需回复请使用<sync>Tag]')
        
    @register.tag(name="connect", description='使用<connect>Tag可以向对方发送连接邀请以实现私密通信，使用这个tag时需要加上at属性，内容为对方的QQ号，输出“<msg>\n\t<connect at="...">Yes</connect>\n</msg>”时表示开始进行连接，外部的Tag要和正常消息一样')
    async def handle_connect_tag(self, value: str, **kwargs) -> list:
        # value 是标签内容，如 <my_tag>value</my_tag>
        # 返回 list[BaseMessageElement]
        q_id: str = kwargs.get('at', '')
        if 'yes' in value.lower() and q_id.isdigit() and not self.connecting:
            self.fake_kira_mac = kira_rand_mac()
            fake_kira_mac = self.encryptor.encrypt_mac(self.fake_kira_mac)
            self.try_to_connect = True
            await self.start_task(300)
            logger.info(f'正在与{q_id}进行连接...')

            return [At(q_id), Text(f'<CNCT>{fake_kira_mac}</CNCT>')]
        else:
            return []
        
    @register.tag(name="back_connect", description="使用<back_connect>Tag可以接受对方的连接邀请以进行私密通信，输出“<msg>\n\t<back_connect>Yes</back_connect>\n</msg>”时表示接受连接，外部的Tag要和正常消息一样，只有出现[System]询问是否接受连接请求时才允许使用，其余情况严禁使用")
    async def handle_back_connect_tag(self, value: str, **kwargs) -> list:
        # value 是标签内容，如 <my_tag>value</my_tag>
        # 返回 list[BaseMessageElement]
        if 'yes' in value.lower() and self.plaintext_kira_mac and not self.connecting:
            self.back_to_connect = True
            ciphertext_kira_mac = self.encryptor.encrypt_string(self.kira_mac, self.plaintext_kira_mac)
            await self.start_task(300)
            logger.info('正在接受对方的连接邀请...')

            return [Text(f'<BCNCT>{ciphertext_kira_mac}</BCNCT>')]
        else:
            return []
        
    @register.tag(name="sync", description="使用<sync>Tag可以与对方进行加密对话，把需要加密的内容放到其内部如“<msg>\n\t<sync>...</sync>\n</msg>”（除了与你连接的人外其余人无法得到明文），外部的Tag要和正常消息一样，不需要加密的内容正常放到<text>Tag内部即可，只有当出现[SYNCLINK]的内容表示已经连通时才可使用，其余情况严禁使用")
    async def handle_sync_tag(self, value: str, **kwargs) -> list:
        # value 是标签内容，如 <my_tag>value</my_tag>
        # 返回 list[BaseMessageElement]
        if self.connecting and self.real_target_kira_mac:
            self.imgencryptor.encrypt_text_to_image(f'kira:{value}', self.imgencryptor.str_to_key(self.real_target_kira_mac), self.image_file)
            logger.info(f'发送了密文：{value}')

            return [Text('<SYNC>'), Image(image=self.image_file), Text('</SYNC>')]
        else:
            return []
    
    @register.tag(name="cancel", description="使用<cancel>Tag可以终止与对方的连接，输出“<msg>\n\t<cancel>Yes</cancel>\n</msg>”时表示取消连接（取消连接后连接状态会直接被重置），外部的Tag要和正常消息一样")
    async def handle_cancel_tag(self, value: str, **kwargs) -> list:
        # value 是标签内容，如 <my_tag>value</my_tag>
        # 返回 list[BaseMessageElement]
        if 'yes' in value.lower():
            await self.reset_link()

        return []
