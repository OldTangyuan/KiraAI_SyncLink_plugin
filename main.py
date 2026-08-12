"""SyncLink 插件入口：KiraAI 插件主体。

负责插件的事件处理与 Tag 编排；加密、图片编解码、KiraMac 混淆等具体实现
已抽到 ``synclink`` 子包（不依赖 KiraAI 核心，可独立测试）。
"""
from core.plugin import BasePlugin, PluginContext, get_logger
from core.plugin import on, Priority
from core.plugin import register
from core.chat import KiraMessageEvent, MessageChain, KiraMessageBatchEvent
from core.chat.message_elements import Text, At, Image
from core.provider import LLMRequest
from core.prompt_manager import Prompt

import asyncio
import json
from pathlib import Path

from synclink import constants as C
from synclink.crypto import KeyCipher, PasswordCipher
from synclink.image_codec import ImageCodec
from synclink.mac import MacObfuscator, kira_rand_mac

logger = get_logger('plugin-SyncLink', 'orange')


class SyncLink(BasePlugin):
    def __init__(self, ctx: PluginContext, cfg: dict):
        super().__init__(ctx, cfg)
        self.data_dir: Path = None
        self.data_file: Path = None

        self.kira_mac = None
        self.fake_kira_mac = None
        self.plaintext_kira_mac = None
        self.real_target_kira_mac = None

        # 加密 / 编解码组件
        self.password_cipher = PasswordCipher()          # 握手阶段口令加密
        self.key_cipher = KeyCipher()                    # 通信阶段 32 字节密钥加密
        self.mac_cipher = MacObfuscator(self.password_cipher)  # KiraMac 混淆
        self.image_codec = ImageCodec()                  # 密文 ⇄ PNG 图片

        self._task: asyncio.Task = None

        # 连接状态
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
            self.data_file.write_text(json.dumps(C.default_data(kira_mac)), encoding="utf-8")
            self.kira_mac = kira_mac
        else:
            self.kira_mac = json.loads(self.data_file.read_text()).get('KiraMac')
        logger.info('SyncLink插件加载完成！')

    async def terminate(self):
        """插件卸载时调用，在此释放资源、取消任务等"""
        # reset_link 内部已调用 cancel_task，无需再重复取消
        await self.reset_link()

    async def cancel_task(self):
        """取消并等待后台任务结束"""
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def start_task(self, t: int):
        """启动一个新的后台任务（旧的先取消）"""
        await self.cancel_task()
        self._task = asyncio.create_task(self._background_loop(t))
        if self._task:
            try:
                await asyncio.sleep(0)
            except asyncio.CancelledError:
                pass

    async def _background_loop(self, t: int):
        """连接超时后台任务：t 秒后强制重置连接并通知"""
        await asyncio.sleep(t)
        try:
            # 本任务即将自然结束，无需取消自身（原实现调用 reset_link 会自我 cancel，
            # 依赖 CancelledError 注入时序，属脆弱逻辑），直接清空状态即可
            self._reset_state()
            # session_id 只在 on_message 收到被 @ 的消息时记录；若从未记录（边界场景），
            # 无法发送通知但仍已完成强制断开，不抛出异常
            session_id = getattr(self, 'session_id', None)
            if session_id:
                await self.send_notice(session_id, C.notice_timeout())
            logger.warning('连接超时，自动中断')
        except asyncio.CancelledError:
            return
        except Exception as e:
            logger.error(f"后台任务异常: {e}")

    async def reset_link(self):
        """重置连接：取消后台任务并清空连接状态"""
        await self.cancel_task()
        self._reset_state()

    def _reset_state(self):
        """仅清空连接状态字段（不触碰后台任务）"""
        self.try_to_connect = False
        self.back_to_connect = False
        self.connecting = False
        self.connect_data = None

        self.fake_kira_mac = None
        self.plaintext_kira_mac = None
        self.real_target_kira_mac = None
        logger.info('连接已重置')

    async def cache_kira_mac(self, kira_mac, nickname, qq_id):
        """缓存连接到的 KiraMac"""
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
        """向指定会话发送系统通知"""
        chain = MessageChain([Text(content)])
        await self.ctx.publish_notice(
            session=session_id,
            chain=chain,
            is_mentioned=True
        )

    async def send_to_group(self, ada_name, group_id, content):
        """向指定群发送纯文本消息"""
        chain = MessageChain([Text(content)])
        await self.ctx.adapter_mgr.get_adapter(ada_name).send_group_message(
            group_id=group_id,
            send_message_obj=chain
        )

    @on.llm_request()
    async def inject_prompt(self, event, req: LLMRequest, tag_set, *args, **kwargs):
        """连接建立后，向系统提示词追加 SyncLink 上下文"""
        if self.connecting:
            req.system_prompt.append(Prompt(
                content=C.SYNCLINK_PROMPT % self.connect_data.get('nickname', ''),
                name="sync_link_context",
                source="SyncLink",
            ))

    @on.im_batch_message()
    async def filter_llm_request(self, event: KiraMessageBatchEvent, *args, **kwargs):
        """
        在 LLM 请求发出前，对用户消息和助手历史消息进行内容替换
        （过滤掉协议标签，避免 AI 被无关噪音干扰）
        """
        for msg in event.messages:
            original = msg.message_str
            filtered = C.FILTER_PATTERN.sub('', original)
            if original != filtered:
                msg.message_str = filtered

    @on.im_message(priority=Priority.HIGH)
    async def on_message(self, event: KiraMessageEvent, *args, **kwargs):
        # 从 chain 中提取纯文本（只取 Text 元素）
        text = "".join(ele.text for ele in event.message.chain if isinstance(ele, Text))
        at = "".join(ele.pid for ele in event.message.chain if isinstance(ele, At))
        image = [ele for ele in event.message.chain if isinstance(ele, Image)]
        real_text = ''
        target_kira_mac = ''
        receive_real_target_kira_mac = ''
        real_target_kira_mac = ''
        image_type = ''
        if event.is_mentioned:
            self.session_id = event.session.__str__()
        stripped = text.strip()
        # ---- 解析阶段：识别握手 / 加密消息协议标签 ----
        if (target_kira_mac := C.CNCT_PATTERN.match(stripped)) and not self.connecting and not self.try_to_connect:
            target_kira_mac = target_kira_mac.group(1)
            self.plaintext_kira_mac = self.mac_cipher.decrypt_mac(target_kira_mac)
        elif (receive_real_target_kira_mac := C.BCNCT_PATTERN.match(stripped)) and not self.connecting and self.try_to_connect:
            receive_real_target_kira_mac = receive_real_target_kira_mac.group(1)
            self.real_target_kira_mac = self.password_cipher.decrypt(receive_real_target_kira_mac, self.fake_kira_mac)
        elif (real_target_kira_mac := C.FCNCT_PATTERN.match(stripped)) and not self.connecting and self.back_to_connect:
            real_target_kira_mac = real_target_kira_mac.group(1)
            self.real_target_kira_mac = self.password_cipher.decrypt(real_target_kira_mac, self.kira_mac)
        elif (image_type := C.SYNC_PATTERN.match(stripped)) and self.connecting and image:
            path = await image[0].to_path()
            try:
                key = self.key_cipher.str_to_key(self.kira_mac)
                real_text = self.key_cipher.decrypt_data(self.image_codec.image_to_bytes(path), key)
            except Exception:
                real_text = ''

        # ---- 动作阶段：根据解析结果推进连接状态 ----
        if self.plaintext_kira_mac and "kira:" in self.plaintext_kira_mac and at == event.message.self_id and target_kira_mac:
            # 收到连接邀请：丢弃原消息并提示 AI 是否接受
            event.discard(True)
            session_id = event.session.__str__()
            sender_name = event.message.sender.nickname
            await self.send_notice(session_id, C.notice_connect_request(sender_name))
        elif self.real_target_kira_mac and "kira:" in self.real_target_kira_mac and receive_real_target_kira_mac:
            # 收到对方接受邀请的应答：完成握手并回传本机 MAC 确认
            await self.cancel_task()
            self.try_to_connect = False
            self.connecting = True
            await self.start_task(C.LINK_TIMEOUT)
            await self.cache_kira_mac(self.real_target_kira_mac, event.message.sender.nickname, event.message.sender.user_id)
            ada_name = event.session.adapter_name
            group_id = event.message.group.group_id
            self_kira_mac = self.password_cipher.encrypt(self.kira_mac, self.real_target_kira_mac)
            await self.send_to_group(ada_name, group_id, f'<FCNCT>{self_kira_mac}</FCNCT>')
            session_id = event.session.__str__()
            sender_name = event.message.sender.nickname
            await self.send_notice(session_id, C.notice_link_established(sender_name))
        elif self.real_target_kira_mac and "kira:" in self.real_target_kira_mac and real_target_kira_mac:
            # 收到对方确认：双方连接建立
            await self.cancel_task()
            self.back_to_connect = False
            self.connecting = True
            await self.start_task(C.LINK_TIMEOUT)
            await self.cache_kira_mac(self.real_target_kira_mac, event.message.sender.nickname, event.message.sender.user_id)
            # 补发成功通知（原实现只有发起方收到，接收方不知情）
            session_id = event.session.__str__()
            sender_name = event.message.sender.nickname
            await self.send_notice(session_id, C.notice_link_established(sender_name))
        elif image_type and image and 'kira:' in real_text:
            # 收到加密消息：丢弃原消息并把明文转告给 AI
            await self.cancel_task()
            event.discard(True)
            session_id = event.session.__str__()
            sender_name = event.message.sender.nickname
            real_text = C.KIRA_PREFIX_PATTERN.sub('', real_text, count=1)
            await self.start_task(C.LINK_TIMEOUT)
            await self.send_notice(session_id, C.notice_encrypted_message(sender_name, real_text))

    @register.tag(name="connect", description='使用<connect>Tag可以向对方发送连接邀请以实现私密通信，使用这个tag时需要加上at属性，内容为对方的QQ号，输出“<msg>\n\t<connect at="...">Yes</connect>\n</msg>”时表示开始进行连接，外部的Tag要和正常消息一样')
    async def handle_connect_tag(self, value: str, **kwargs) -> list:
        # value 是标签内容，如 <my_tag>value</my_tag>
        # 返回 list[BaseMessageElement]
        q_id: str = kwargs.get('at', '')
        if 'yes' in value.lower() and q_id.isdigit() and not self.connecting:
            self.fake_kira_mac = kira_rand_mac()
            fake_kira_mac = self.mac_cipher.encrypt_mac(self.fake_kira_mac)
            self.try_to_connect = True
            await self.start_task(C.HANDSHAKE_TIMEOUT)
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
            ciphertext_kira_mac = self.password_cipher.encrypt(self.kira_mac, self.plaintext_kira_mac)
            await self.start_task(C.HANDSHAKE_TIMEOUT)
            logger.info('正在接受对方的连接邀请...')

            return [Text(f'<BCNCT>{ciphertext_kira_mac}</BCNCT>')]
        else:
            return []

    @register.tag(name="sync", description="使用<sync>Tag可以与对方进行加密对话，把需要加密的内容放到其内部如“<msg>\n\t<sync>...</sync>\n</msg>”（除了与你连接的人外其余人无法得到明文），外部的Tag要和正常消息一样，不需要加密的内容正常放到<text>Tag内部即可，只有当出现[SYNCLINK]的内容表示已经连通时才可使用，其余情况严禁使用")
    async def handle_sync_tag(self, value: str, **kwargs) -> list:
        # value 是标签内容，如 <my_tag>value</my_tag>
        # 返回 list[BaseMessageElement]
        if self.connecting and self.real_target_kira_mac:
            key = self.key_cipher.str_to_key(self.real_target_kira_mac)
            encrypted_data = self.key_cipher.encrypt_data(f'kira:{value}', key)
            self.image_codec.bytes_to_image(encrypted_data, self.image_file)
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
