"""
    Utils
    Written by Pair7z
"""

lower_alpha = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
               'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']


upper_alpha = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
               'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']


def contain_alpha(s):
    """
    检测s是否含有字母
    :param s:检测的字符串
    :return: True/False
    """
    for c in s:
        if c.isalpha():
            return True
    return False


def get_pure_alpha(s):
    """
    获得纯含有英文字母的字符串, 去除其他一切符号
    :param s: 待处理的文本
    :return:  pure_alpha_text
    """
    pure_alpha_text = ''
    for c in s:
        if c.isalpha:
            pure_alpha_text = pure_alpha_text + c
    return pure_alpha_text


def is_pure_alpha_str(s):
    """
    判断s是否是由纯字母组成的
    :param s: 待判断字符串
    :return: True/False
    """
    for c in s:
        if not c.isalpha():
            return False
    return True

def get_alpha_by_order(order):
    """
    通过字母顺序0~26获得小写字母
    :param order:
    :return:
    """
    pass


def str2bitstream(s : str,rule):
    """
    字符串以rule编码 返回其编码的01比特流 8位对齐
    :param s:字符串
    :param rule:编码规则 如'utf-8' 'GBK'
    :return: 01流的字符串
    """
    s_bytes = s.encode(rule)
    # [2:]去掉前导0x
    stream_arr = [ bin(int(c))[2:].rjust(8,'0') for c in s_bytes]
    return ''.join(stream_arr)

def bitstream2str(stream : str, rule):
    """
    01比特流转化为字符串 以rule编码
    :param stream:比特流字符串
    :param rule:编码规则
    :return:字符串
    """
    if len(stream)%8 != 0:
        raise SyntaxError('stream should be divisible by 8')
    bytes_hex = hex(int(stream,2))
    return bytes.fromhex(bytes_hex[2:]).decode(rule)

def bytes2bitstream(btyes_ : bytes):
    """
    将bytes转化为01流字符串 每字节补齐8位
    :param btyes_:
    :return:
    """
    res = ''
    for byte in btyes_:
        res = res + bin(byte)[2:].rjust(8, '0')
    return res


def grouping(s :str,l:int):
    """
    将字符串按l等长分割成数组
    :param s: 待分割字符串
    :param l: 长度
    :return: 数组
    """
    return [s[i:i+l] for i in range(0,len(s),l)]

def substitution_equal_length(process_str : str, change_table : list) -> str:
    """
    等长置换
    :param process_str:被置换的字符串
    :param change_table:置换表 列表 要求置换表下标从1开始
    :return: str
    """
    str_list = list(process_str)
    for i in range(len(str_list)):
        str_list[i] = process_str[change_table[i]-1]
    return ''.join(str_list)

def xor_bits(bits1 : str, bits2 : str) -> str:
    """
    逐位异或运算
    :param bits1: str
    :param bits2: str
    :return: str
    """
    assert len(bits1)==len(bits2), 'length of bits1 must be equal to length of bits2'
    n = len(bits1)
    res = ['0' for i in range(n)]
    for i in range(n):
        res[i] = str(int(bits1[i])^int(bits2[i]))
    return ''.join(res)

def sum_mod2_bits(bits1 : str, bits2 : str) -> str:
    """
    两个01串模2相加
    :param bits1: str
    :param bits2: str
    :return: str
    """
    return xor_bits(bits1, bits2)


def bitstr_rol(bits : str, m : int) -> str:
    """
    将01比特流循环左移m位
    :param bits: 比特流串
    :param n: 左移m位
    :return: str
    """
    bits_list = list(bits)
    n = len(bits)
    for i in range(n):
        bits_list[i] = bits[(i+m)%n]
    return ''.join(bits_list)


if __name__ == '__main__':
    print(bitstr_rol('123456',2))
