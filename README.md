# KiraAI_SyncLink_plugin
这个KiraAI的插件可以让你的AI与拥有同插件的AI进行连接，且能加密通信。你可能会问，这有什么用。哈哈，确实没用，但是它够酷😎

> 🔗 两个都安装了本插件的 KiraAI 可以互相「连上线」，然后通过加密图片传递悄悄话——密文长什么样，只有通信双方知道。

---

## 📑 目录

- [功能特性](#功能特性)
- [工作原理](#工作原理)
- [安装与依赖](#安装与依赖)
- [快速开始](#快速开始)
- [Tag 一览](#tag-一览)
- [加密机制详解](#加密机制详解)
- [数据文件](#数据文件)
- [项目结构](#项目结构)
- [安全说明](#安全说明)
- [开源协议](#开源协议)

---

## ✨ 功能特性

- **加密通信**：连接建立后，消息使用 AES-256-GCM 加密，再编码进一张 PNG 图片发送，双方之外的人看到的只是一张乱码图。
- **三步握手**：通过 `<connect>` / `<back_connect>` / `<cancel>` 等 Tag 完成连接的建立与断开，过程无需人工干预。
- **AI 友好**：连接成功后会自动向系统提示词注入「已连接」上下文，让 AI 知道该在什么时机使用加密 Tag。
- **协议过滤**：`<CNCT>` / `<BCNCT>` / `<FCNCT>` / `<SYNC>` 等协议标签会在送入大模型之前被过滤，避免 AI 被无关噪音干扰。
- **超时保护**：连接阶段 5 分钟、已连接状态 30 分钟没有活动，会自动断开并重置连接状态。
- **连接记录**：历史连接对象的 KiraMac、昵称、QQ 号会缓存在本地 `data.json` 中。

## 🔧 工作原理

每个插件实例在首次加载时会生成一个唯一的 **KiraMac**（形如 `kira:12:34:56:78:9a:bc`），它就是这台 AI 在 SyncLink 网络里的「身份证」。两台 AI 通过三步握手交换彼此的 KiraMac，之后就能用对方的 KiraMac 作为密钥进行加密通信。

### 连接流程（三步握手）

| 步骤 | 触发者 | 使用的 Tag | 传输内容 |
| --- | --- | --- | --- |
| 1. 发起连接 | 发起方 | `<connect at="对方QQ">Yes</connect>` | `<CNCT>`：携带一个「假 MAC」的混淆密文 |
| 2. 接受连接 | 被邀请方 | `<back_connect>Yes</back_connect>` | `<BCNCT>`：用「假 MAC」加密的真实 MAC |
| 3. 确认连接 | 发起方（插件自动） | 无需操作 | `<FCNCT>`：用对方真实 MAC 加密的本机 MAC |

三步完成后，双方都持有对方的真实 MAC，连接即建立。

### 加密通信

连接建立后，发送方把 `kira:<要加密的内容>` 用「接收方的 KiraMac」派生密钥进行 AES-256-GCM 加密，把密文字节直接写入一张 PNG 图片的 RGB 像素通道（PngBin 方案），再以 `<SYNC>` 标签 + 图片的形式发出。接收方用自己的 KiraMac 从图片中解出密文并解密，解出的明文会以 `[SYNCLINK]` 提示的方式转告给接收方的 AI。

> 因为发送方加密用的密钥 = 接收方解密用的密钥（都是接收方自己的 KiraMac），所以只有这两台 AI 能互相解开，群里的其他人都看不到明文。

## 📦 安装与依赖

1. 将本插件目录（`main.py`、`manifest.json`、`requirements.txt`）放入 KiraAI 的插件目录。
2. 安装依赖：

```bash
pip install -r requirements.txt
```

依赖清单：

| 依赖 | 用途 |
| --- | --- |
| `cryptography` | AES-256-GCM 加密、PBKDF2 密钥派生 |
| `numpy` | 图片像素编码（PngBin 方案） |
| `Pillow`（PIL） | 图片读写 |

> ✅ `Pillow` 已在 `requirements.txt` 中显式声明（`main.py` 中 `from PIL import Image` 依赖它）。

## 🚀 快速开始

> 前提：发起方与被邀请方需在同一个群里，且都已安装本插件并加载成功（日志出现 `SyncLink插件加载完成！`）。

1. **发起连接**：在群里 `@对方AI` 并输出连接 Tag，例如：

   ```
   <msg>
     <connect at="10001">Yes</connect>
   </msg>
   ```

2. **接受连接**：被邀请方会收到 `[System] ... 发起了连接请求 ...` 的提示。若同意，回复：

   ```
   <msg>
     <back_connect>Yes</back_connect>
   </msg>
   ```

3. **开始加密对话**：握手完成后，双方会收到 `[SYNCLINK] 已成功建立与 ... 的连接` 的提示，之后即可使用 `<sync>`：

   ```
   <msg>
     <sync>这是只有我俩能看到的悄悄话</sync>
   </msg>
   ```

4. **断开连接**：需要结束时：

   ```
   <msg>
     <cancel>Yes</cancel>
   </msg>
   ```

## 🏷️ Tag 一览

| Tag | 作用 | 使用前提 |
| --- | --- | --- |
| `<connect at="QQ号">Yes</connect>` | 向对方发起加密连接邀请 | 当前未连接 |
| `<back_connect>Yes</back_connect>` | 接受对方的连接邀请 | 收到 `[System]` 连接请求提示之后 |
| `<sync>...</sync>` | 与对方进行加密对话 | 出现 `[SYNCLINK]` 已连通提示之后 |
| `<cancel>Yes</cancel>` | 终止当前连接并重置状态 | 任意时刻 |

> 约定：`<msg>` 等外层 Tag 要与正常消息保持一致；`<sync>` 里放需要加密的内容，不需要加密的内容放在普通 `<text>` Tag 里即可。

## 🔒 加密机制详解

插件中有两层「加密」，定位完全不同：

**1. 握手阶段（`Encryptor`）**

- `encrypt_mac / decrypt_mac`：把 MAC 的每个字符转成 ASCII 码，再在随机位置夹入一段随机字母数字作为「密钥」。**这只是混淆，不是真正的加密**，仅用于握手时临时传递「假 MAC」。
- `encrypt_string / decrypt_string`：标准 AES-256-GCM，密钥由 PBKDF2-HMAC-SHA256（600,000 次迭代、16 字节随机盐）派生，输出格式为 `Base64(salt(16B) + nonce(12B) + ciphertext_with_tag)`。用于在握手时加密真实 MAC。

**2. 通信阶段（`ImageEncryptor`）**

- AES-256-GCM，密钥直接取「接收方 KiraMac」字符串的前 32 字节（不足用 `\0` 补齐）。
- 密文格式：`salt(16B) + nonce(12B) + ciphertext_with_tag`。
- 密文通过 PngBin 方案写入 PNG 图片的 RGB 像素通道进行传输。

## 🗂️ 数据文件

插件数据存放在 KiraAI 的插件数据目录（`get_plugin_data_dir()`）下：

- **`data.json`**：本机 KiraMac 与历史连接记录，首次加载自动生成：

  ```json
  {
    "KiraMac": "kira:12:34:56:78:9a:bc",
    "CachedKiraMac": [
      { "KiraMac": "kira:...", "nickname": "对方AI昵称", "qq_id": 10001 }
    ]
  }
  ```

- **`encrypted_message.png`**：加密消息的临时图片文件，每次发送 `<sync>` 时生成。

## 📁 项目结构

```
KiraAI_SyncLink_plugin/
├── main.py             # 插件入口：事件处理与 Tag 编排
├── manifest.json       # 插件清单：名称、版本、作者、描述
├── requirements.txt    # Python 依赖（含 Pillow）
├── README.md           # 本文档
├── LICENSE.txt         # 开源协议（AGPL-3.0）
├── synclink/           # 核心实现子包（纯逻辑，不依赖 KiraAI 核心，可独立测试）
│   ├── constants.py    #   常量、协议正则、提示文案
│   ├── crypto.py       #   AES-256-GCM 加密（口令 / 32 字节密钥两套）
│   ├── image_codec.py  #   密文 ⇄ PNG 图片（PngBin 方案）
│   └── mac.py          #   KiraMac 生成与混淆
└── tests/              # 回归验证脚本
    ├── reference_original.py  #   重构前的原逻辑副本（验证基准，勿改动）
    └── verify_synclink.py     #   新旧实现逐字节兼容验证
```

### 开发验证

重构后如需确认逻辑未变，可在项目内虚拟环境运行验证脚本：

```bash
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
.venv\Scripts\python -m tests.verify_synclink
```

## ⚠️ 安全说明

- 本项目定位是「炫技向」的玩具插件，**不适用于高安全要求的场景**。
- 握手阶段的 MAC 加密只是混淆，可被轻易逆向；真正保护通信内容的是通信阶段的 AES-256-GCM。
- 通信密钥由 KiraMac 派生，而 KiraMac 只有 6 字节（48 bit）随机性，密钥强度有限；任何人若拿到接收方的 KiraMac，都能解密其收到的历史消息。
- 明文、KiraMac 及历史连接记录以明文形式存储在本地 `data.json` 中，请妥善保管该文件。

## 📄 开源协议

本项目基于 **GNU AGPL v3.0** 开源，详见 [LICENSE.txt](./LICENSE.txt)。

---

*SyncLink —— 让两台 AI 偷偷说悄悄话的插件 🤫😎*
