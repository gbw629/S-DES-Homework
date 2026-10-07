import tkinter as tk
from tkinter import ttk, messagebox
import time


# ===================== 基础工具函数 =====================
def permute(bits, table):
    """
    通用置换函数
    :param bits: 输入的二进制位列表
    :param table: 1-based的置换表元组
    :return: 置换后的二进制位列表
    """
    return [bits[i - 1] for i in table]


def left_shift(bits, n):
    """
    循环左移n位
    :param bits: 输入的二进制位列表
    :param n: 左移位数
    :return: 左移后的二进制位列表
    """
    n = n % len(bits)
    return bits[n:] + bits[:n]


def bin_str_to_bits(bin_str):
    """二进制字符串转bit列表"""
    return [int(c) for c in bin_str]


def bits_to_bin_str(bits):
    """bit列表转二进制字符串"""
    return ''.join(str(b) for b in bits)


def ascii_to_bits(text):
    """ASCII字符串转bit列表（每个字符占8位，高位在前）"""
    bits = []
    for char in text:
        ascii_val = ord(char)
        for i in range(7, -1, -1):
            bits.append((ascii_val >> i) & 1)
    return bits


def bits_to_ascii(bits):
    """bit列表转ASCII字符串（每8位解析一个字符）"""
    text = ''
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) < 8:
            break
        ascii_val = 0
        for b in byte:
            ascii_val = (ascii_val << 1) | b
        text += chr(ascii_val)
    return text


# ===================== 密钥生成模块 =====================
def generate_keys(key_10):
    """
    10位密钥扩展，生成两个8位子密钥k1、k2
    :param key_10: 10位密钥的bit列表
    :return: k1, k2 两个8位子密钥
    """
    P10 = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
    P8 = (6, 3, 7, 4, 8, 5, 10, 9)

    # P10置换
    p10_out = permute(key_10, P10)
    left = p10_out[:5]
    right = p10_out[5:]

    # 左移1位生成k1
    left_ls1 = left_shift(left, 1)
    right_ls1 = left_shift(right, 1)
    combined_ls1 = left_ls1 + right_ls1
    k1 = permute(combined_ls1, P8)

    # 再左移2位生成k2
    left_ls2 = left_shift(left_ls1, 2)
    right_ls2 = left_shift(right_ls1, 2)
    combined_ls2 = left_ls2 + right_ls2
    k2 = permute(combined_ls2, P8)

    return k1, k2


# ===================== 轮函数F模块 =====================
def s_box_lookup(bits, sbox):
    """
    S盒查找函数：第1位和第4位为行号，第2位和第3位为列号
    :param bits: 4位输入bit列表
    :param sbox: 4x4的S盒二维数组
    :return: 2位输出bit列表
    """
    row = bits[0] * 2 + bits[3]
    col = bits[1] * 2 + bits[2]
    val = sbox[row][col]
    return [val // 2, val % 2]


def f(right_4, subkey):
    """
    S-DES轮函数F
    :param right_4: 4位右半部分输入
    :param subkey: 8位子密钥
    :return: 4位轮函数输出
    """
    EP = (4, 1, 2, 3, 2, 3, 4, 1)
    SP = (2, 4, 3, 1)
    # 作业指定的S盒（SBox2与PPT不同，以此为准）
    SBOX1 = [
        [1, 0, 3, 2],
        [3, 2, 1, 0],
        [0, 2, 1, 3],
        [3, 1, 0, 2]
    ]
    SBOX2 = [
        [0, 1, 2, 3],
        [2, 3, 1, 0],
        [3, 0, 1, 2],
        [2, 1, 0, 3]
    ]

    # 扩展置换EP
    ep_out = permute(right_4, EP)
    # 与子密钥异或
    xor_out = [a ^ b for a, b in zip(ep_out, subkey)]
    # 拆分后进入S盒
    left_s = xor_out[:4]
    right_s = xor_out[4:]
    s1_out = s_box_lookup(left_s, SBOX1)
    s2_out = s_box_lookup(right_s, SBOX2)
    s_out = s1_out + s2_out
    # SP置换
    sp_out = permute(s_out, SP)
    return sp_out


# ===================== 核心加解密函数（已修正） =====================
def encrypt_block(plain_8, k1, k2):
    """
    单组8位明文加密（标准S-DES流程：IP -> fk1 -> SW -> fk2 -> IP^-1）
    :param plain_8: 8位明文bit列表
    :param k1: 子密钥1
    :param k2: 子密钥2
    :return: 8位密文bit列表
    """
    IP = (2, 6, 3, 1, 4, 8, 5, 7)
    IP_INV = (4, 1, 3, 5, 7, 2, 8, 6)

    # 1. 初始置换
    ip_out = permute(plain_8, IP)
    L, R = ip_out[:4], ip_out[4:]

    # 2. 第一轮fk1：仅左半部分异或轮函数结果，右半不变
    L = [a ^ b for a, b in zip(L, f(R, k1))]

    # 3. SW：左右交换
    L, R = R, L

    # 4. 第二轮fk2：仅左半部分异或轮函数结果，右半不变
    L = [a ^ b for a, b in zip(L, f(R, k2))]

    # 5. 最终置换
    pre_output = L + R
    cipher = permute(pre_output, IP_INV)
    return cipher


def decrypt_block(cipher_8, k1, k2):
    """
    单组8位密文解密（子密钥逆序使用，流程与加密完全对称）
    :param cipher_8: 8位密文bit列表
    :param k1: 子密钥1
    :param k2: 子密钥2
    :return: 8位明文bit列表
    """
    IP = (2, 6, 3, 1, 4, 8, 5, 7)
    IP_INV = (4, 1, 3, 5, 7, 2, 8, 6)

    # 1. 初始置换
    ip_out = permute(cipher_8, IP)
    L, R = ip_out[:4], ip_out[4:]

    # 2. 第一轮先用k2
    L = [a ^ b for a, b in zip(L, f(R, k2))]

    # 3. SW：左右交换
    L, R = R, L

    # 4. 第二轮用k1
    L = [a ^ b for a, b in zip(L, f(R, k1))]

    # 5. 最终置换
    pre_output = L + R
    plain = permute(pre_output, IP_INV)
    return plain


# ===================== 字符串加解密（扩展功能） =====================
def encrypt_string(plain_text, key_str):
    """ASCII字符串加密，输出二进制密文字符串"""
    key_bits = bin_str_to_bits(key_str)
    k1, k2 = generate_keys(key_bits)
    plain_bits = ascii_to_bits(plain_text)

    cipher_bits = []
    # 按8位分组，不足补0
    for i in range(0, len(plain_bits), 8):
        block = plain_bits[i:i+8]
        if len(block) < 8:
            block += [0] * (8 - len(block))
        cipher_block = encrypt_block(block, k1, k2)
        cipher_bits.extend(cipher_block)
    return bits_to_bin_str(cipher_bits)


def decrypt_string(cipher_bin_str, key_str):
    """二进制密文字符串解密，输出ASCII明文字符串"""
    key_bits = bin_str_to_bits(key_str)
    k1, k2 = generate_keys(key_bits)
    cipher_bits = bin_str_to_bits(cipher_bin_str)

    plain_bits = []
    for i in range(0, len(cipher_bits), 8):
        block = cipher_bits[i:i+8]
        if len(block) < 8:
            block += [0] * (8 - len(block))
        plain_block = decrypt_block(block, k1, k2)
        plain_bits.extend(plain_block)

    plain_text = bits_to_ascii(plain_bits)
    return plain_text.rstrip('\x00')  # 去除补位的空字符


# ===================== 暴力破解（第4关） =====================
def brute_force(plain_str, cipher_str):
    """
    暴力破解10位密钥
    :param plain_str: 8位明文二进制字符串
    :param cipher_str: 8位密文二进制字符串
    :return: (找到的密钥列表, 耗时秒数)
    """
    plain_bits = bin_str_to_bits(plain_str)
    cipher_bits = bin_str_to_bits(cipher_str)
    start_time = time.time()
    found_keys = []

    # 遍历所有10位密钥（0~1023）
    for key_int in range(0, 1024):
        key_str = format(key_int, '010b')
        key_bits = bin_str_to_bits(key_str)
        k1, k2 = generate_keys(key_bits)
        encrypted = encrypt_block(plain_bits, k1, k2)
        if encrypted == cipher_bits:
            found_keys.append(key_str)

    elapsed = time.time() - start_time
    return found_keys, elapsed


# ===================== 封闭性测试（第5关） =====================
def collision_test(plain_str, num_keys=1024):
    """
    测试多密钥碰撞：不同密钥加密同一明文是否得到相同密文
    :param plain_str: 8位明文二进制字符串
    :param num_keys: 测试的密钥数量
    :return: 碰撞字典 {密文: [密钥列表]}
    """
    plain_bits = bin_str_to_bits(plain_str)
    cipher_to_keys = {}

    for key_int in range(num_keys):
        key_str = format(key_int, '010b')
        key_bits = bin_str_to_bits(key_str)
        k1, k2 = generate_keys(key_bits)
        cipher_bits = encrypt_block(plain_bits, k1, k2)
        cipher_str = bits_to_bin_str(cipher_bits)

        if cipher_str in cipher_to_keys:
            cipher_to_keys[cipher_str].append(key_str)
        else:
            cipher_to_keys[cipher_str] = [key_str]

    # 筛选出存在多个密钥的密文
    collisions = {c: ks for c, ks in cipher_to_keys.items() if len(ks) > 1}
    return collisions


# ===================== GUI 图形界面 =====================
class SDESApp:
    def __init__(self, root):
        self.root = root
        self.root.title("S-DES 加密解密工具")
        self.root.geometry("650x550")

        # 标签页切换
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)

        # 初始化各个功能页
        self._init_basic_tab()      # 第1关：基本测试
        self._init_ascii_tab()      # 第3关：ASCII字符串加密
        self._init_brute_tab()      # 第4关：暴力破解
        self._init_collision_tab()  # 第5关：封闭性测试

    def _init_basic_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text='基本测试')

        ttk.Label(frame, text='8位明文/密文 (二进制):').grid(row=0, column=0, padx=5, pady=12, sticky='w')
        self.entry_plain = ttk.Entry(frame, width=32)
        self.entry_plain.grid(row=0, column=1, padx=5, pady=12)
        self.entry_plain.insert(0, '10101010')

        ttk.Label(frame, text='10位密钥 (二进制):').grid(row=1, column=0, padx=5, pady=12, sticky='w')
        self.entry_key = ttk.Entry(frame, width=32)
        self.entry_key.grid(row=1, column=1, padx=5, pady=12)
        self.entry_key.insert(0, '1010000010')

        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=10)
        ttk.Button(btn_frame, text='加密', command=self._encrypt_basic).pack(side='left', padx=10)
        ttk.Button(btn_frame, text='解密', command=self._decrypt_basic).pack(side='left', padx=10)

        ttk.Label(frame, text='运算结果:').grid(row=3, column=0, padx=5, pady=12, sticky='w')
        self.label_result = ttk.Label(frame, text='', foreground='#0066cc', font=('微软雅黑', 10, 'bold'))
        self.label_result.grid(row=3, column=1, padx=5, pady=12, sticky='w')

    def _encrypt_basic(self):
        plain_str = self.entry_plain.get().strip()
        key_str = self.entry_key.get().strip()
        if not self._check_8bit(plain_str) or not self._check_10bit(key_str):
            return
        plain_bits = bin_str_to_bits(plain_str)
        key_bits = bin_str_to_bits(key_str)
        k1, k2 = generate_keys(key_bits)
        cipher_bits = encrypt_block(plain_bits, k1, k2)
        self.label_result.config(text=f'密文: {bits_to_bin_str(cipher_bits)}')

    def _decrypt_basic(self):
        cipher_str = self.entry_plain.get().strip()
        key_str = self.entry_key.get().strip()
        if not self._check_8bit(cipher_str) or not self._check_10bit(key_str):
            return
        cipher_bits = bin_str_to_bits(cipher_str)
        key_bits = bin_str_to_bits(key_str)
        k1, k2 = generate_keys(key_bits)
        plain_bits = decrypt_block(cipher_bits, k1, k2)
        self.label_result.config(text=f'明文: {bits_to_bin_str(plain_bits)}')

    def _init_ascii_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text='ASCII加密')

        ttk.Label(frame, text='明文字符串 (ASCII):').grid(row=0, column=0, padx=5, pady=10, sticky='nw')
        self.text_plain = tk.Text(frame, height=5, width=45)
        self.text_plain.grid(row=0, column=1, padx=5, pady=10)
        self.text_plain.insert('1.0', 'This is a test')

        ttk.Label(frame, text='10位密钥 (二进制):').grid(row=1, column=0, padx=5, pady=10, sticky='w')
        self.entry_key_ascii = ttk.Entry(frame, width=32)
        self.entry_key_ascii.grid(row=1, column=1, padx=5, pady=10, sticky='w')
        self.entry_key_ascii.insert(0, '1010000010')

        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=8)
        ttk.Button(btn_frame, text='加密', command=self._encrypt_ascii).pack(side='left', padx=10)
        ttk.Button(btn_frame, text='解密', command=self._decrypt_ascii).pack(side='left', padx=10)

        ttk.Label(frame, text='二进制密文:').grid(row=3, column=0, padx=5, pady=10, sticky='nw')
        self.text_cipher_bin = tk.Text(frame, height=5, width=45)
        self.text_cipher_bin.grid(row=3, column=1, padx=5, pady=10)

        ttk.Label(frame, text='解密结果:').grid(row=4, column=0, padx=5, pady=10, sticky='nw')
        self.text_decrypt = tk.Text(frame, height=5, width=45)
        self.text_decrypt.grid(row=4, column=1, padx=5, pady=10)

    def _encrypt_ascii(self):
        plain_text = self.text_plain.get('1.0', 'end').strip()
        key_str = self.entry_key_ascii.get().strip()
        if not self._check_10bit(key_str):
            return
        cipher_bin = encrypt_string(plain_text, key_str)
        self.text_cipher_bin.delete('1.0', 'end')
        self.text_cipher_bin.insert('1.0', cipher_bin)

    def _decrypt_ascii(self):
        cipher_bin = self.text_cipher_bin.get('1.0', 'end').strip()
        key_str = self.entry_key_ascii.get().strip()
        if not self._check_10bit(key_str) or not all(c in '01' for c in cipher_bin):
            messagebox.showerror('错误', '输入不合法')
            return
        plain_text = decrypt_string(cipher_bin, key_str)
        self.text_decrypt.delete('1.0', 'end')
        self.text_decrypt.insert('1.0', plain_text)

    def _init_brute_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text='暴力破解')

        ttk.Label(frame, text='8位明文 (二进制):').grid(row=0, column=0, padx=5, pady=10, sticky='w')
        self.entry_brute_plain = ttk.Entry(frame, width=32)
        self.entry_brute_plain.grid(row=0, column=1, padx=5, pady=10)
        self.entry_brute_plain.insert(0, '10101010')

        ttk.Label(frame, text='8位密文 (二进制):').grid(row=1, column=0, padx=5, pady=10, sticky='w')
        self.entry_brute_cipher = ttk.Entry(frame, width=32)
        self.entry_brute_cipher.grid(row=1, column=1, padx=5, pady=10)
        self.entry_brute_cipher.insert(0, '00100100')

        ttk.Button(frame, text='开始暴力破解', command=self._run_brute).grid(row=2, column=0, columnspan=2, pady=12)

        ttk.Label(frame, text='破解结果:').grid(row=3, column=0, padx=5, pady=10, sticky='nw')
        self.text_brute_result = tk.Text(frame, height=12, width=55)
        self.text_brute_result.grid(row=3, column=1, padx=5, pady=10)

    def _run_brute(self):
        plain_str = self.entry_brute_plain.get().strip()
        cipher_str = self.entry_brute_cipher.get().strip()
        if not self._check_8bit(plain_str) or not self._check_8bit(cipher_str):
            return
        found_keys, elapsed = brute_force(plain_str, cipher_str)
        self.text_brute_result.delete('1.0', 'end')
        self.text_brute_result.insert('1.0', f'总耗时: {elapsed:.4f} 秒\n')
        self.text_brute_result.insert('end', f'共找到 {len(found_keys)} 个有效密钥:\n')
        for k in found_keys:
            self.text_brute_result.insert('end', f'  {k}\n')

    def _init_collision_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text='封闭性测试')

        ttk.Label(frame, text='8位明文 (二进制):').grid(row=0, column=0, padx=5, pady=10, sticky='w')
        self.entry_col_plain = ttk.Entry(frame, width=32)
        self.entry_col_plain.grid(row=0, column=1, padx=5, pady=10)
        self.entry_col_plain.insert(0, '10101010')

        ttk.Label(frame, text='测试密钥数量 (1-1024):').grid(row=1, column=0, padx=5, pady=10, sticky='w')
        self.entry_col_num = ttk.Entry(frame, width=32)
        self.entry_col_num.grid(row=1, column=1, padx=5, pady=10)
        self.entry_col_num.insert(0, '1024')

        ttk.Button(frame, text='开始碰撞测试', command=self._run_collision).grid(row=2, column=0, columnspan=2, pady=12)

        ttk.Label(frame, text='测试结果:').grid(row=3, column=0, padx=5, pady=10, sticky='nw')
        self.text_col_result = tk.Text(frame, height=12, width=55)
        self.text_col_result.grid(row=3, column=1, padx=5, pady=10)

    def _run_collision(self):
        plain_str = self.entry_col_plain.get().strip()
        num_str = self.entry_col_num.get().strip()
        if not self._check_8bit(plain_str):
            return
        try:
            num_keys = int(num_str)
            if not 1 <= num_keys <= 1024:
                raise ValueError
        except ValueError:
            messagebox.showerror('错误', '密钥数量必须是1-1024之间的整数')
            return

        collisions = collision_test(plain_str, num_keys)
        self.text_col_result.delete('1.0', 'end')
        if not collisions:
            self.text_col_result.insert('1.0', '测试范围内未发现碰撞：不同密钥加密结果均唯一\n')
        else:
            self.text_col_result.insert('1.0', f'发现 {len(collisions)} 组密文碰撞（多密钥对应同一密文）：\n\n')
            for cipher, keys in list(collisions.items())[:5]:
                self.text_col_result.insert('end', f'密文 {cipher} 对应密钥：\n')
                for k in keys:
                    self.text_col_result.insert('end', f'    {k}\n')
                self.text_col_result.insert('end', '\n')
            if len(collisions) > 5:
                self.text_col_result.insert('end', f'... 剩余 {len(collisions)-5} 组未展示\n')

    # 输入校验辅助函数
    def _check_8bit(self, s):
        if len(s) != 8 or not all(c in '01' for c in s):
            messagebox.showerror('错误', '必须输入8位二进制字符串')
            return False
        return True

    def _check_10bit(self, s):
        if len(s) != 10 or not all(c in '01' for c in s):
            messagebox.showerror('错误', '密钥必须是10位二进制字符串')
            return False
        return True


if __name__ == '__main__':
    root = tk.Tk()
    app = SDESApp(root)
    root.mainloop()
