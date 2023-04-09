"""
    PyCompiler
    Web服务接口
"""
import sys
from classic_method import *
from des_cypher import DES_Cypher
from flask import Flask, request, make_response,jsonify
from gevent.pywsgi import WSGIServer
import json
app = Flask(__name__)

"""
恺撒密码
"""
@app.route('/caesarEncrypt', methods = ['POST'])
def caesar_encrypt():
    try:
        caesarCipher = CaesarCipher()
        raw_data = request.get_data()
        req_data = json.loads(raw_data)
        plain_text = req_data['plainText']
        key = req_data['key']
        assert key.isdigit(), "key必须为大于等于0的数字"
        cipher_text = caesarCipher.encrypt(plain_text, int(key))
        result =  {'plainText': plain_text, 'key': key, 'cipherText': cipher_text}
        data = {'result': result, 'code':1, 'msg':'加密成功!'}
        return jsonify(data)
    except Exception as e:
        data = {'code':0, 'msg':'加密失败, 出现错误', 'result':str(e)}
        return jsonify(data)

@app.route('/caesarDecrypt', methods = ['POST'])
def caesar_decrypt():
    try:
        caesarCipher = CaesarCipher()
        raw_data = request.get_data()
        req_data = json.loads(raw_data)
        cipher_text = req_data['cipherText']
        key = req_data['key']
        assert key.isdigit(), "key必须为大于等于0的数字"
        plain_text = caesarCipher.decrypt(cipher_text, int(key))
        result =  {'plainText': plain_text, 'key': key, 'cipherText': cipher_text}
        data = {'result': result, 'code':1, 'msg':'解密成功!'}
        return jsonify(data)
    except Exception as e:
        data = {'code':0, 'msg':'解密失败, 出现错误', 'result':str(e)}
        return jsonify(data)

"""
playfair密码
"""
@app.route('/playfairEncrypt', methods=['POST'])
def flayfair_encrypt():
    try:
        playfairCipher = PlayfairCipher()
        raw_data = request.get_data()
        req_data = json.loads(raw_data)
        plain_text = req_data['plainText']
        key = req_data['key']
        cipher_text = playfairCipher.encrypt(plain_text, key)
        key_table = playfairCipher.get_key_table(key)
        result = {'plainText': plain_text, 'key': key, 'cipherText': cipher_text, 'keyTable': key_table}
        data = {'result': result, 'code': 1, 'msg': '加密成功!'}
        return jsonify(data)
    except Exception as e:
        data = {'code': 0, 'msg': '加密失败, 出现错误', 'result': str(e)}
        return jsonify(data)


@app.route('/playfairDecrypt', methods=['POST'])
def playfair_decrypt():
    try:
        playfairCipher = PlayfairCipher()
        raw_data = request.get_data()
        req_data = json.loads(raw_data)
        cipher_text = req_data['cipherText']
        key = req_data['key']
        plain_text = playfairCipher.decrypt(cipher_text, key)
        key_table = playfairCipher.get_key_table(key)
        result = {'plainText': plain_text, 'key': key, 'cipherText': cipher_text, 'keyTable': key_table}
        data = {'result': result, 'code': 1, 'msg': '解密成功!'}
        return jsonify(data)
    except Exception as e:
        data = {'code': 0, 'msg': '解密失败, 出现错误', 'result': str(e)}
        return jsonify(data)

"""
维吉尼亚密码
"""

@app.route('/virginiaEncrypt', methods=['POST'])
def virginia_encrypt():
    try:
        virginiaCipher = VirginiaCipher()
        raw_data = request.get_data()
        req_data = json.loads(raw_data)
        plain_text = req_data['plainText']
        key = req_data['key']
        cipher_text = virginiaCipher.encrypt(plain_text, key)
        result = {'plainText': plain_text, 'key': key, 'cipherText': cipher_text}
        data = {'result': result, 'code': 1, 'msg': '加密成功!'}
        return jsonify(data)
    except Exception as e:
        data = {'code': 0, 'msg': '加密失败, 出现错误', 'result': str(e)}
        return jsonify(data)


@app.route('/virginiaDecrypt', methods=['POST'])
def virginia_decrypt():
    try:
        virginiaCipher = VirginiaCipher()
        raw_data = request.get_data()
        req_data = json.loads(raw_data)
        cipher_text = req_data['cipherText']
        key = req_data['key']
        plain_text = virginiaCipher.decrypt(cipher_text, key)
        result = {'plainText': plain_text, 'key': key, 'cipherText': cipher_text}
        data = {'result': result, 'code': 1, 'msg': '解密成功!'}
        return jsonify(data)
    except Exception as e:
        data = {'code': 0, 'msg': '解密失败, 出现错误', 'result': str(e)}
        return jsonify(data)

@app.route('/desEncrypt', methods=['POST'])
def des_encrypt():
    try:
        des_cypher = DES_Cypher()
        raw_data = request.get_data()
        req_data = json.loads(raw_data)
        plain_text = req_data['plainText']
        key = req_data['key']
        cipher_text = des_cypher.encrypt(plain_text, key)
        result = {'plainText': plain_text, 'key': key, 'cipherText': cipher_text}
        data = {'result': result, 'code': 1, 'msg': '加密成功!'}
        return jsonify(data)
    except Exception as e:
        data = {'code': 0, 'msg': '加密失败, 出现错误', 'result': str(e)}
        return jsonify(data)


@app.route('/desDecrypt', methods=['POST'])
def des_decrypt():
    try:
        desCipher = DES_Cypher()
        raw_data = request.get_data()
        req_data = json.loads(raw_data)
        cipher_text = req_data['cipherText']
        key = req_data['key']
        plain_text = desCipher.decrypt(cipher_text, key)
        result = {'plainText': plain_text, 'key': key, 'cipherText': cipher_text}
        data = {'result': result, 'code': 1, 'msg': '解密成功!'}
        return jsonify(data)
    except Exception as e:
        data = {'code': 0, 'msg': '解密失败, 出现错误', 'result': str(e)}
        return jsonify(data)


@app.after_request
def func_res(resp):
    res = make_response(resp)
    res.headers['Access-Control-Allow-Origin'] = '*'
    res.headers['Access-Control-Allow-Methods'] = 'GET,POST'
    res.headers['Access-Control-Allow-Headers'] = 'x-requested-with,content-type'
    return res


if __name__ == "__main__":
    app.run('',10010,debug=True)
    # Serve the app with gevent
    print("Web Service running in http://localhost:10010/")
    http_server = WSGIServer(('0.0.0.0',10010), app)
    http_server.serve_forever()
