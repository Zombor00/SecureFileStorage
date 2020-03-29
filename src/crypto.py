from base64 import b64encode,b64decode
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import AES,PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad,unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Hash import SHA
from Crypto import Random

def create_key():
    '''
        Nombre: create_key
        Descripcion: Genera un par clave publica-privada de RSA de 2048 bits.
        Argumentos:
        Retorno:
            Tupla en el que el primer elemento es la clave publica y el segundo elemento es la clave privada en formato pem.
    '''

    keyObject = RSA.generate(2048)
    key = [0,0]
    key[0] = keyObject.publickey().export_key().decode("utf-8")
    key[1] = keyObject.export_key().decode("utf-8")
    return key


def encrypt(stream):
    '''
        Nombre: encrypt
        Descripcion: Encripta con AES con modo de encadenamiento CBC, con IV de 16 bytes, y longitud de clave de 256 bits.
        Argumentos:
            stream: Mensaje a encriptar
        Retorno:
            Diccionario con los valores "iv"(vector de inicializacion), "ciphertext"(mensaje cifrado) y "key"(clave simétrica usada para encriptar).
    '''
    try:
        stream = stream.encode("utf-8")
    except:
        pass
    iv = get_random_bytes(16)
    key_bytes = get_random_bytes(32)
    cipher = AES.new(key_bytes, AES.MODE_CBC,iv)
    ciphertext_bytes = cipher.encrypt(pad(stream, AES.block_size))
    ivb64 = b64encode(cipher.iv).decode('utf-8')
    ciphertext = b64encode(ciphertext_bytes).decode('utf-8')
    key = b64encode(key_bytes).decode('utf-8')

    return {'iv':ivb64, 'ciphertext':ciphertext, 'key':key}

def decrypt(stream,key,iv,signed):
    '''
        Nombre: decrypt
        Descripcion: Desencripta un mensaje encriptado con AES con modo de encadenamiento CBC, con IV de 16 bytes, y longitud de clave de 256 bits.
        Argumentos:
            stream: Mensaje a desencriptar con AES.
            key: Clave simetrica que usa AES para encriptar-desencriptar.
            iv: Vector de inicializacion que usa AES en modo CBC.
            signed: True si el mensaje lleva firma, False si no esta firmado.
        Retorno:
            El stream desencriptado.
    '''
    iv_bytes = b64decode(iv)
    stream_bytes = b64decode(stream)
    key_bytes = b64decode(key)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
    pt = unpad(cipher.decrypt(stream_bytes), AES.block_size)
    if(signed):
        return(pt[256:].decode("utf-8"),pt[:256])
    return (pt.decode("utf-8"))

def sign(stream,privKey):
    '''
        Nombre: sign
        Descripcion: Devuelve el mensaje firmado con una clave privada.
        Argumentos:
            stream: Mensaje a encriptar.
            privKey: Llave privada del emisor usada para firmar.
        Retorno:
            El mensaje con la firma concatenada delante. 
    '''

    privKey = privKey.encode("utf-8")

    #Calculamos el sha256 del mensaje
    streamBytes = stream.encode("utf-8")
    hashedStream = SHA256.new(data = streamBytes)

    # Generamos la firma
    firma = pkcs1_15.new(RSA.import_key(privKey.decode("utf-8"))).sign(hashedStream)

    #Devolvemos la firma concatenada
    return firma + streamBytes

def verify_sign(stream,pubKey,firma):
    '''
        Nombre: verify_sign
        Descripcion: Comprueba la autenticidad del mensaje
        Argumentos:
            stream: Mensaje a verificar.
            pubKey: Llave publica del emisor usada para verificar.
            firma: Firma con la que se compara. 
        Retorno:
            True si la autenticidad es correcta y False en caso contrario.
    '''
 
    pubKey = pubKey.encode("utf-8")

    #Calculamos el sha256 del mensaje
    try:
        streamBytes = stream.encode("utf-8")
    except:
        streamBytes = stream
    hashedStream = SHA256.new(data = streamBytes)

    #Comprobamos la autenticidad del mensaje
    try:
        pkcs1_15.new(RSA.import_key(pubKey.decode("utf-8"))).verify(hashedStream, firma)
        #print("The signature is valid.")
        return True
    except (ValueError, TypeError):
        #print("The signature is not valid.")
        return False


def enc_sign(stream,privKey,pubKey):
    '''
        Nombre: enc_sign
        Descripcion: Aplicamos un mensaje híbrido para firmar y encriptar: firma un mensaje usando RSA, encripta el mensaje firmado usando AES y luego genera un sobre digital con la clave simetrica.
        Argumentos:
            stream: Mensaje a firmar y encriptar
            privKey: clave privada del emisor usada para la firma digital.
            pubKey: clave publica del receptor usada para generar el sobredigital.
        Retorno:
            Devuelve un string con los 16 primeros bytes el IV usado, los siguientes 32 bytes la clave simetrica usada, y los últimos el mensaje firmado y cifrado.
    '''

    #Firmamos
    streamFirmado = sign(stream,privKey)

    #Encriptamos el mensaje firmado
    encrypted = encrypt(streamFirmado)

    #Generamos el sobre digital
    cipher_rsa = PKCS1_v1_5.new(RSA.import_key(pubKey))
    sobreDigital = cipher_rsa.encrypt(encrypted["key"].encode("utf-8"))
     
    return b64decode(encrypted["iv"]) + sobreDigital + encrypted["ciphertext"].encode("utf-8")

def dec_sign(stream,privKey,pubKey):
    '''
        Nombre: dec_sign
        Descripcion: Desencripta el mensaje encriptado en enc_sign y verifica su autenticidad.
        Argumentos:
            stream: Mensaje a desencriptar y verificar su autenticidad
            privKey: Llave privada del receptor para desencriptar el sobre digital
            pubKey: Llave publica del emisor usada para verificar la autenticidad del mensaje
        Retorno:
            Devuelve el mensaje descifrado y None si la signature no es valida.
    '''

    iv = b64encode(stream[:16]).decode("utf-8")
    claveCifrada = stream[16:16 + 256]
    mensajeCifrado = stream[16 + 256:]

    dsize = SHA.digest_size
    sentinel = Random.new().read(15+dsize)

    cipher_rsa = PKCS1_v1_5.new(RSA.import_key(privKey))
    claveSimetrica = cipher_rsa.decrypt(claveCifrada, sentinel)

    #Desciframos el mensaje
    mensajeDescifrado = decrypt(mensajeCifrado, claveSimetrica, iv,True)

    #Comprobamos la autenticidad del mensaje
    if(verify_sign(mensajeDescifrado[0], pubKey, mensajeDescifrado[1])):
       return mensajeDescifrado[0]
    return None

#key = create_key()
#print(key)
#x = encrypt("wtf")
#print("Encrypt:")
#print(x)
#print("Decrypt:")
#print(decrypt(x["ciphertext"],x["key"],x["iv"],False))
#print("Signed:")
#x = sign("wtf",key[1])
#print(x)
#print("Verified")
#print(verify_sign(x[256:],key[0],x[:256]))
#x = enc_sign("jajaxdkbueno",key[1],key[0])
#print("Mensaje firmado y cifrado:")
#print(x)
#y = dec_sign(x,key[1],key[0])
#print("Mensaje descifrado y autentificado:")
#print(y)
