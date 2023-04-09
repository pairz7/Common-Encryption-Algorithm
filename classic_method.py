"""
古典加密方法
written by Pair7z
主要包括
    恺撒密码
    Playfair加密
    维吉尼亚加密
"""
import utils


class ClassicCipher(object):
    def get_method_name(self):
        """
            获得加密方法的名称
            :return cipher_method_name 加密方法名称
        """
        pass

    def encrypt(self, plain_text, key):
        """
            加密
            :param plain_text 明文
            :param key 秘钥
            :return cipher_text 密文
        """
        pass

    def decrypt(self, cipher_text, key):
        """
            解密
            :param cipher_text 密文
            :param key 秘钥
            :return plain_text 明文
        """
        pass


class CaesarCipher(ClassicCipher):
    """
        恺撒密码
    """

    def get_method_name(self):
        return "Caesar"

    def encrypt(self, plain_text, key):
        """
            加密
            :param plain_text 明文
            :param key: int 秘钥 这里指在字母表里偏移多少次
            :return cipher_text 密文
            只处理字母
        """
        key = key % 26
        cipher_text = ''
        for c in plain_text:
            cipher_c = c
            if c.islower():
                cipher_c = chr((ord(c) - ord('a') + key) % 26 + ord('a'))
            if c.isupper():
                cipher_c = chr((ord(c) - ord('A') + key) % 26 + ord('A'))
            cipher_text = cipher_text + cipher_c
        return cipher_text

    def decrypt(self, cipher_text, key):
        """
            解密
            :param cipher_text 密文
            :param key 秘钥 这里指在字母表里偏移多少次
            :return plain_text 明文
            只处理小写字母 将大写字母全转换为小写
        """
        key = key % 26
        plain_text = ''
        for c in cipher_text:
            plain_c = c
            if c.islower():
                plain_c = chr((ord(c) - ord('a') - key) % 26 + ord('a'))
            if c.isupper():
                plain_c = chr((ord(c) - ord('A') - key) % 26 + ord('A'))
            plain_text = plain_text + plain_c
        return plain_text


class PlayfairCipher(ClassicCipher):
    """
        Playfair加密
        将大小写统一转换为小写
    """

    def __init__(self, irr_chr = 'x'):
        # 无关字符
        self.irr_chr = irr_chr

    def get_method_name(self):
        return 'Playfair'

    def get_index(self, table, c):
        """
        :param table: 密码表
        :param c: 查找的字符
        :return: (i, j)
        """
        for i in range(5):
            for j in range(5):
                if table[i][j] == c:
                    return i, j
        return -1, -1

    def get_plain_group(self, pure_text):
        """
        获得明文的两两分组 进行下一步加密 两个相同字符填充irr_chr 末尾单出来的填充irr_chr
        :param pure_text:
        :return: list -> group
        """
        group = []
        tmp = ''
        i = 0
        while i < len(pure_text):
            c = pure_text[i]
            if len(tmp) == 0:
                tmp = tmp + c
                i += 1
            elif len(tmp) == 1:
                if c == tmp[0]:
                    tmp = tmp + self.irr_chr
                else:
                    tmp = tmp + c
                    i += 1
            else:
                group.append(tmp)
                tmp = ''
        if len(tmp) == 2:
            group.append(tmp)
            tmp = ''
        if len(tmp) == 1:
            tmp = tmp + self.irr_chr
            group.append(tmp)
        return group

    def group_encrypt(self, table, ele):
        """
        将2位长的词组进行加密
        加密方法:
            1. 同行 统一右移一位%5
            2. 同列 统一下移一位%5
            3. 对角线 另一个对角线
        :param table:密码表
        :param ele:元素  e.g. 'ab'
        :return: 加密后的元素 'cd'
        """
        i0, j0 = self.get_index(table, ele[0])
        i1, j1 = self.get_index(table, ele[1])
        res = [self.irr_chr, self.irr_chr]
        # 同行
        if i0 == i1:
            res[0] = table[i0][(j0 + 1) % 5]
            res[1] = table[i1][(j1 + 1) % 5]
        elif j0 == j1:
            res[0] = table[(i0 + 1) % 5][j0]
            res[1] = table[(i1 + 1) % 5][j1]
        else:
            res[0] = table[i0][j1]
            res[1] = table[i1][j0]
        return ''.join(res)

    def encrypt(self, plain_text, key: str):
        """
            加密
            :param plain_text 明文
            :param key 秘钥 这里指在字母表里偏移多少次
            :return cipher_text 密文
            只处理字母
        """
        assert utils.contain_alpha(key), "密钥应为英文字母组合"
        plain_text = plain_text.lower()
        plain_text = plain_text.replace('j', 'i')
        key_table = self.get_key_table(key)
        pure_text = utils.get_pure_alpha(plain_text)
        plain_group = self.get_plain_group(pure_text)
        res = [self.group_encrypt(key_table, ele) for ele in plain_group]
        return ''.join(res)

    def group_decrypt(self, table, ele):
        """
        将2位长的词组进行解密
        加密方法:
            1. 同行 统一左移一位%5
            2. 同列 统一上移一位%5
            3. 对角线 另一个对角线
        :param table:密码表
        :param ele:元素  e.g. 'ab'
        :return: 解密后的元素 'cd'
        """
        i0, j0 = self.get_index(table, ele[0])
        i1, j1 = self.get_index(table, ele[1])
        res = [self.irr_chr, self.irr_chr]
        # 同行
        if i0 == i1:
            res[0] = table[i0][(j0 - 1) % 5]
            res[1] = table[i1][(j1 - 1) % 5]
        elif j0 == j1:
            res[0] = table[(i0 - 1) % 5][j0]
            res[1] = table[(i1 - 1) % 5][j1]
        else:
            res[0] = table[i0][j1]
            res[1] = table[i1][j0]
        return ''.join(res)

    def decrypt(self, cipher_text, key):
        """
        解密
        :param cipher_text:str 密文
        :param key: 密钥
        :return:
        """
        assert utils.contain_alpha(key), "密钥应为英文字母组合"
        cipher_text = cipher_text.lower()
        cipher_text = cipher_text.replace('j', 'i')
        key_table = self.get_key_table(key)
        pure_text = utils.get_pure_alpha(cipher_text)
        cipher_group = self.get_plain_group(pure_text)
        res = [self.group_decrypt(key_table, ele) for ele in cipher_group]
        return ''.join(res)
        pass

    def get_key_table(self, key: str):
        key = key.lower()
        key = key.replace('j', 'i')
        table = [['' for i in range(5)] for j in range(5)]
        real_key = ''
        for c in key:
            if c.isalpha() and c not in real_key:
                real_key = real_key + c
        left_alpha = ''
        for c in utils.lower_alpha:
            if c not in real_key and c != 'j':
                left_alpha = left_alpha + c
        real_key = real_key + left_alpha
        i = 0
        j = 0
        for c in real_key:
            if j >= 5:
                i += 1
                j = 0
            table[i][j] = c
            j += 1
        return table


class VirginiaCipher(ClassicCipher):
    """
    维吉尼亚密码
    """
    def get_method_name(self):
        return 'Virginia'


    def get_offset(self, c):
        """
        获得字母的偏移量 大写字母为相对于'A'的offset  小写字母则为'a'的偏移量
        :param c: 字母
        :return: offset -> int
        """
        if c.islower():
            return ord(c) - ord('a')
        elif c.isupper():
            return ord(c) - ord('A')
        else:
            return 0

    def get_next_key_c(self):
        self.next_i = self.next_i % self.key_len
        res = self.key[self.next_i]
        self.next_i += 1
        return res

    def encrypt(self, plain_text, key):
        assert utils.is_pure_alpha_str(key), '密钥key应为纯字母串'
        cipher_text = ''
        self.key = key
        self.key_len = len(key)
        self.next_i = 0
        for c in plain_text:
            cipher_c = c
            if c.isupper():
                cipher_c = chr((ord(cipher_c) - ord('A') + self.get_offset(self.get_next_key_c())) % 26 + ord('A'))
            elif c.islower():
                cipher_c = chr((ord(cipher_c) - ord('a') + self.get_offset(self.get_next_key_c())) % 26 + ord('a'))
            cipher_text = cipher_text + cipher_c
        return cipher_text



    def decrypt(self, cipher_text, key):
        assert utils.is_pure_alpha_str(key), '密钥key应为纯字母串'
        plain_text = ''
        self.key = key
        self.key_len = len(key)
        self.next_i = 0
        for c in cipher_text:
            plain_c = c
            if c.isupper():
                plain_c = chr((ord(plain_c) - ord('A') - self.get_offset(self.get_next_key_c())) % 26 + ord('A'))
            elif c.islower():
                plain_c = chr((ord(plain_c) - ord('a') - self.get_offset(self.get_next_key_c())) % 26 + ord('a'))
            plain_text = plain_text + plain_c
        return plain_text


if __name__ == '__main__':
    original = 'Hello, my world, I love you!'
    key = 'FuckYou'
    v = VirginiaCipher()
    print(v.encrypt(original, key))
    print(v.decrypt(v.encrypt(original, key),key))