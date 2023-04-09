"""
DES对称加密
Written by pair7z
2023-04-08
utf-8进行编码解码
"""
import binascii
import utils
import base64

# IP置换
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

IP_REVERSE = [40, 8, 48, 16, 56, 24, 64, 32,
              39, 7, 47, 15, 55, 23, 63, 31,
              38, 6, 46, 14, 54, 22, 62, 30,
              37, 5, 45, 13, 53, 21, 61, 29,
              36, 4, 44, 12, 52, 20, 60, 28,
              35, 3, 43, 11, 51, 19, 59, 27,
              34, 2, 42, 10, 50, 18, 58, 26,
              33, 1, 41, 9, 49, 17, 57, 25]

# E盒
E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

# S盒
S = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ]
]

# P table
P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

# PC table
PC1 = [57, 49, 41, 33, 25, 17, 9,
      1, 58, 50, 42, 34, 26, 18,
      10, 2, 59, 51, 43, 35, 27,
      19, 11, 3, 60, 52, 44, 36,
      63, 55, 47, 39, 31, 23, 15,
      7, 62, 54, 46, 38, 30, 22,
      14, 6, 61, 53, 45, 37, 29,
      21, 13, 5, 28, 20, 12, 4]

PC2 = [ 14, 17, 11, 24, 1, 5,
        3, 28, 15,  6, 21, 10,
        23, 19, 12,  4, 26,  8,
        16,  7, 27, 20, 13,  2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32 ]

LEFT_SHIFT = [1, 1, 2, 2, 2, 2, 2 ,2,
              1, 2, 2, 2, 2, 2, 2, 1]

class DES_Cypher():
    def __init__(self, encode_rule='utf-8'):
        self.encode_rule = encode_rule

    def get_bit_group(self, text):
        """
        将text转化为比特流 64一位分组 最后一组补0到64位
        :param text:
        :return:
        """
        stream = utils.str2bitstream(text, self.encode_rule)
        group = utils.grouping(stream, 64)
        group[-1] = group[-1].ljust(64, '0')
        return group

    def handle_64bit(self, plain_bit, keys):
        """
        处理64位明文比特流
        1.IP置换
        2. 16轮 加密
        :param plain_bit:64位明文比特流
        :param keys: 16个子秘钥
        :return: 加密后的64bit
        """
        after_ip = utils.substitution_equal_length(plain_bit, IP)
        L32, R32 = utils.grouping(after_ip, 32)
        for i in range(16):
            L32, R32 = self.round_encrypt(L32, R32, keys[i])
        after_round = R32 + L32
        return utils.substitution_equal_length(after_round, IP_REVERSE)


    def E_table_expansion(self, plain_32bit: str) -> str:
        """
        E表扩充
        :param plain_32bit:
        :return: 48bit
        """
        res = ['' for i in range(48)]
        for i, new_i in enumerate(E):
            res[i] = plain_32bit[new_i - 1]
        return ''.join(res)

    def S_box_substitution(self, s_6bit_group):
        """
        S盒代换
        :param s_6bit_group:
        :return: 32bit str
        """
        res = ''
        for i in range(8):
            s_box = S[i]
            s_6bit = s_6bit_group[i]
            i = int(s_6bit[0] + s_6bit[5], 2)
            j = int(s_6bit[1:5], 2)
            res = res + str(bin(s_box[i][j]))[2:].rjust(4, '0')
        return res

    def PC1_box_substitution(self, key64bit):
        """
        PC1盒置换
        :param key64bit: 64bit
        :return: 56bit
        """
        res = ['' for i in range(56)]
        for i, new_i in enumerate(PC1):
            res[i] = key64bit[new_i - 1]
        return ''.join(res)

    def PC2_box_substitution(self, key56bit):
        """
        PC1盒置换
        :param key64bit: 56bit
        :return: 48bit
        """
        res = ['' for i in range(48)]
        for i, new_i in enumerate(PC2):
            res[i] = key56bit[new_i - 1]
        return ''.join(res)

    def round_func(self, plain_32bit, key_48bit):
        """
        轮函数
        1.E表扩充得到48bit
        2.与key_Bit逐位异或 xor
        3.S盒变换 得到32bit
        4.P置换
        :param plain_32bit: 32长的比特流
        :param key_48bit: 48长的密钥比特流
        :return: 32位的加密比特流
        """
        after_e = self.E_table_expansion(plain_32bit)
        after_xor_with_key = utils.xor_bits(after_e, key_48bit)
        s_6bit_group = utils.grouping(after_xor_with_key, 6)
        # S-box substitution
        after_s = self.S_box_substitution(s_6bit_group)
        after_p = utils.substitution_equal_length(after_s, P)
        return after_p

    def round_encrypt(self, L32, R32, key_bit):
        """
        轮加密
        :param L32: 左部32位流
        :param R32: 右端32位流
        :param key_bit: 密钥48位流
        :return:
        """
        after_F = self.round_func(R32, key_bit)
        R_out = utils.sum_mod2_bits(after_F, L32)
        return R32, R_out

    def get_round_key(self, key):
        """
        计算16轮子秘钥
        :param key: raw str
        :return: 48位的16个密钥列表
        """
        key_bit_group = self.get_bit_group(key)
        key64bit = key_bit_group[0]
        res = []
        after_pc1 = self.PC1_box_substitution(key64bit)
        C, D = utils.grouping(after_pc1, 28)
        for i in range(16):
            C = utils.bitstr_rol(C, LEFT_SHIFT[i])
            D = utils.bitstr_rol(D, LEFT_SHIFT[i])
            res.append(self.PC2_box_substitution(C+D))
        return res



    def encrypt(self, plain_text, key):
        """
        DES加密
        :param plain_text:明文
        :param key: 密钥
        :return: cypher_text 密文 base64编码
        """
        assert len(plain_text), '明文不能为空'
        assert len(key), '密钥不能为空'
        plain_bit_group = self.get_bit_group(plain_text)
        keys = self.get_round_key(key)
        cypher_bit_group = []
        for plain_bit in plain_bit_group:
            cypher_bit_group.append(self.handle_64bit(plain_bit, keys))
        cypher_bits = ''.join(cypher_bit_group)
        cypher_bytes = bytes([int(x, 2) for x in utils.grouping(cypher_bits, 8)])
        return str(base64.b64encode(cypher_bytes))[2:-1]

    def decrypt(self, cypher_text, key):
        """
        DES解密
        :param cypher_text: base64编码后的密文
        :param key: 密钥
        :return: 明文
        """
        assert len(cypher_text), '明文不能为空'
        assert len(key), '密钥不能为空'
        cypher_bytes = base64.b64decode(cypher_text)
        cypher_bits =utils.bytes2bitstream(cypher_bytes)
        cypher_bit_group = utils.grouping(cypher_bits, 64)
        cypher_bit_group[-1] = cypher_bit_group[-1].ljust(64, '0')
        keys = self.get_round_key(key)[::-1]
        plain_bit_group = []
        for plain_bit in cypher_bit_group:
            plain_bit_group.append(self.handle_64bit(plain_bit, keys))
        plain_bits = ''.join(plain_bit_group)
        try:
            return utils.bitstream2str(plain_bits, self.encode_rule)
        except:
            raise Exception('解密失败,密钥可能有误')
        



if __name__ == '__main__':
    des_cypher = DES_Cypher()
    # print(des_cypher.encrypt('2','1')