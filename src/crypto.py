from base64 import b64encode,b64decode
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import AES,PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad,unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Hash import SHA
from Crypto import Random

def createKey():
    keyObject = RSA.generate(2048)
    key = [0,0]
    key[0] = keyObject.publickey().export_key()
    key[1] = keyObject.export_key()
    return key


def encrypt(stream):
    iv = get_random_bytes(16)
    key_bytes = get_random_bytes(32)
    cipher = AES.new(key_bytes, AES.MODE_CBC,iv)
    ciphertext_bytes = cipher.encrypt(pad(stream, AES.block_size))
    ivb64 = b64encode(cipher.iv).decode('utf-8')
    ciphertext = b64encode(ciphertext_bytes).decode('utf-8')
    key = b64encode(key_bytes).decode('utf-8')

    return {'iv':ivb64, 'ciphertext':ciphertext, 'key':key}

def decrypt(stream,key,iv,signed):
    iv_bytes = b64decode(iv)
    stream_bytes = b64decode(stream)
    key_bytes = b64decode(key)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
    pt = unpad(cipher.decrypt(stream_bytes), AES.block_size)
    if(signed):
        return(pt[:-256].decode("utf-8"),pt[-256:])
    return (pt.decode("utf-8"))

def sha256(stream):
    hashedStream = SHA256.new(data=stream)
    return hashedStream

def sign(stream,privKey):
    #Calculamos el sha256 del mensaje
    streamBytes = stream.encode("utf-8")
    hashedStream = sha256(streamBytes)

    # Generamos la firma
    firma = pkcs1_15.new(RSA.import_key(privKey.decode("utf-8"))).sign(hashedStream)

    #Devolvemos la firma concatenada
    return streamBytes + firma

def enc_sign(stream,privKey,pubKey):
    #Firmamos
    streamFirmado = sign(stream,privKey)

    #Encriptamos el mensaje firmado
    encrypted = encrypt(streamFirmado)

    #Generamos el sobre digital
    cipher_rsa = PKCS1_v1_5.new(RSA.import_key(pubKey.decode("utf-8")))
    sobreDigital = cipher_rsa.encrypt(encrypted["key"].encode("utf-8"))
     
    return b64decode(encrypted["iv"]) + sobreDigital + encrypted["ciphertext"].encode("utf-8")

def dec_sign(stream,privKey,pubKey):
    iv = b64encode(stream[:16]).decode("utf-8")
    claveCifrada = stream[16:16 + 256]
    mensajeCifrado = stream[16 + 256:]

    dsize = SHA.digest_size
    sentinel = Random.new().read(15+dsize)

    cipher_rsa = PKCS1_v1_5.new(RSA.import_key(privKey.decode("utf-8")))
    claveSimetrica = cipher_rsa.decrypt(claveCifrada, sentinel)

    #Desciframos el mensaje
    mensajeDescifrado = decrypt(mensajeCifrado, claveSimetrica, iv,True)

    #Calculamos el sha256 del mensaje
    mensajeBytes = mensajeDescifrado[0].encode("utf-8")
    hashedMensaje = sha256(mensajeBytes)

    #Comprobamos la autenticidad del mensaje
    try:
        pkcs1_15.new(RSA.import_key(pubKey.decode("utf-8"))).verify(hashedMensaje, mensajeDescifrado[1])
        print("The signature is valid.")
    except (ValueError, TypeError):
        print("The signature is not valid.")

    return mensajeDescifrado[0]



#key = createKey()
#x = enc_sign("jajaxdkbueno",key[1],key[0])
#print("Mensaje firmado y cifrado:")
#print(x)
#y = dec_sign(x,key[1],key[0])
#print("Mensaje descifrado:")
#print(y)
