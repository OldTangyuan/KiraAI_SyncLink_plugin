"""PngBin 图片编解码：把二进制数据写入 PNG 的 RGB 像素通道，或从图片还原数据。"""
import numpy as np
from PIL import Image as PILImage


class ImageCodec:
    """把二进制数据编码为 PNG 图片（PngBin 方案），或从图片还原二进制数据。"""

    def bytes_to_image(self, data: bytes, output_path: str, width=None):
        """将二进制数据编码为 PNG 图片，返回 ``(宽度, 高度)``。"""
        if not data:
            raise ValueError("没有数据可编码")
        # 每像素存 3 字节 (RGB)
        total_pixels_needed = (len(data) + 2) // 3
        if width is None:
            width = int(total_pixels_needed ** 0.5) + 1
        height = (total_pixels_needed + width - 1) // width

        # 创建像素数组，按行优先填充 RGB 通道
        pixels = np.zeros((height, width, 3), dtype=np.uint8)
        data_index = 0
        data_len = len(data)
        for y in range(height):
            for x in range(width):
                for c in range(3):  # R, G, B
                    if data_index < data_len:
                        pixels[y, x, c] = data[data_index]
                        data_index += 1
                    else:
                        pixels[y, x, c] = 0

        PILImage.fromarray(pixels, 'RGB').save(output_path, 'PNG')
        print(f"图像已保存至: {output_path} (尺寸: {width}x{height})")
        return width, height

    def image_to_bytes(self, image_path: str) -> bytes:
        """从 PNG 图片解码出原始二进制数据。

        数据以最后一个非零字节为结尾（加密数据为随机字节，末尾几乎不可能是 0，
        故这种简化方式安全）。
        """
        img = PILImage.open(image_path)
        pixels = np.array(img)
        height, width, _ = pixels.shape

        data = bytearray()
        for y in range(height):
            for x in range(width):
                for c in range(3):  # R, G, B
                    data.append(pixels[y, x, c])

        last_non_zero = len(data) - 1
        while last_non_zero >= 0 and data[last_non_zero] == 0:
            last_non_zero -= 1
        return bytes(data[:last_non_zero + 1])
