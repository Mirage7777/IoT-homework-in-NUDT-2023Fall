import base64
from Crypto.Cipher import DES
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import asyncio
import websockets

# DES密钥
key = "abcdefgh"

# RSA密钥
random_generator = Random.new().read
rsa = RSA.generate(2048, random_generator)
# 生成私钥
private_key = rsa.exportKey()
# 生成公钥
public_key = rsa.publickey().exportKey()

with open('rsa_private_key.pem', 'wb')as f:
    f.write(private_key)
with open('rsa_public_key.pem', 'wb')as f:
    f.write(public_key)

# DES加密
def des_encrypt(key, plaintext):
    key = key.encode('utf-8')
    plaintext = plaintext.encode('utf-8')
    
    # 填充明文
    length = 8 - (len(plaintext) % 8)
    plaintext += bytes([length]) * length
    
    # 初始化加密器
    cipher = DES.new(key, DES.MODE_ECB)
    
    # 加密
    ciphertext = cipher.encrypt(plaintext)
    
    return ciphertext

# DES解密
def des_decrypt(key, ciphertext):
    key = key.encode('utf-8')
    
    # 初始化解密器
    cipher = DES.new(key, DES.MODE_ECB)
    
    # 解密
    plaintext = cipher.decrypt(ciphertext)
    
    # 去除填充
    plaintext = plaintext[:-plaintext[-1]]
    
    return plaintext.decode('utf-8')

def get_key(key_file):
    with open(key_file) as f:
        data = f.read()
        key = RSA.importKey(data)
    return key

# RSA加密
def encrypt_data(msg):
    public_key = get_key('rsa_public_key.pem')
    cipher = PKCS1_v1_5.new(public_key)
    encrypt_text = base64.b64encode(cipher.encrypt(bytes(msg.encode("utf8"))))
    return encrypt_text.decode('utf-8')

# RSA解密
def decrypt_data(encrypt_msg):
    private_key = get_key('rsa_private_key.pem')
    cipher = PKCS1_v1_5.new(private_key)
    back_text = cipher.decrypt(base64.b64decode(encrypt_msg), 0)
    return back_text.decode('utf-8')

# 利用RSA加密DES密钥
encrypted_key = encrypt_data(key)

IP_ADDR = "127.0.0.8"
IP_PORT = "8888"
 
# 握手，通过接收hello，发送"check"来进行双方的握手。
async def serverHands(websocket):
    while True:
        recv_text = await websocket.recv()
        print("recv_text=" + recv_text)
        if recv_text == "hello":
            print("connected success")
            await websocket.send("check")
            return True
        else:
            await websocket.send("connected fail")
 
 
# 接收从客户端发来的消息并处理，再返给客户端ok
async def serverRecv(websocket):
    recv_text = await websocket.recv()
    print("<<<", recv_text)
    await websocket.send("OK client.This is your public key.Please send your encrypted key.\n" + public_key.decode())
    recv_text = await websocket.recv()
    print("<<<", recv_text)
    print("##########Decoding##########\nciphertext：",recv_text[26:],"\nplaintext：",decrypt_data(recv_text[26:]))
    await websocket.send("Gotcha.We can chat now.")
    while True:
        recv_text = await websocket.recv()
        print("<<<", recv_text)
        dd = des_decrypt(key,recv_text)
        print("\n##########Decoding##########\nciphertext：",recv_text,"\nplaintext：",dd)
        input_text = input("input text:")
        ed = des_encrypt(key,input_text)
        print("\n##########Encoding##########\nplaintext：",input_text,"\nciphertext：",ed)
        await websocket.send(ed)
 
# 握手并且接收数据
async def serverRun(websocket, path):
    print(path)
    await serverHands(websocket)
 
    await serverRecv(websocket)
 
#main function
if __name__ == '__main__':
    print("======server main begin======")
    server = websockets.serve(serverRun, IP_ADDR, IP_PORT)
    asyncio.get_event_loop().run_until_complete(server)
    asyncio.get_event_loop().run_forever()