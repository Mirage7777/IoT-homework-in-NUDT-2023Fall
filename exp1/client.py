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
 
# 握手，通过发送hello，接收"check"来进行双方的握手。
async def clientHands(websocket):
    while True:
        await websocket.send("hello")
        response_str = await websocket.recv()
        if "check" in response_str:
            print("shake hands successfully")
            return True
 
 
# 向服务器端发送消息
async def clientSend(websocket):
    await websocket.send("Hello server,I want to connect with you!")
    print("<<<", await websocket.recv())
    await websocket.send("This is my encrypted key.\n" + encrypted_key)
    print("<<<", await websocket.recv())
    while True:
        input_text = input("input text: ")
        if input_text == "exit":
            print(f'"exit", bye!')
            await websocket.close(reason="exit")
            return False
        ed = des_encrypt(key,input_text)
        print("\n##########Encoding##########\nplaintext：",input_text,"\nciphertext：",ed)
        await websocket.send(ed)
        recv_text = await websocket.recv()
        print("<<<", recv_text)
        dd = des_decrypt(key,recv_text)
        print("\n##########Decoding##########\nciphertext：",recv_text,"\nplaintext：",dd)
 
 
# 进行websocket连接
async def clientRun():
    ipaddress = IP_ADDR + ":" + IP_PORT
    async with websockets.connect("ws://" + ipaddress) as websocket:
        await clientHands(websocket)
 
        await clientSend(websocket)
 
#main function
if __name__ == '__main__':
    print("======client main begin======")
    asyncio.get_event_loop().run_until_complete(clientRun())