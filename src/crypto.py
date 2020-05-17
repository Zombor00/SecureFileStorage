'''
    crypto.py
    Modulo encargado del apartado criptográfico de securebox
    @author Alejandro Bravo, Miguel Gonzalez
    @version 1.0
    @date 30-03-2020
'''

from Crypto.Signature import pkcs1_15
from Crypto.Cipher import AES,PKCS1_v1_5,PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad,unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Hash import SHA
from Crypto import Random

def create_key(pwd):
    '''
        Nombre: create_key
        Descripcion: Genera un par clave publica-privada de RSA de 2048 bits.
        Argumentos:
            pwd: Contraseña con la que se guarda la clave privada.
        Retorno:
            Tupla en el que el primer elemento es la clave publica y el segundo elemento es la clave privada en formato pem.
    '''
    print("-> Generando claves...",end='')
    keyObject = RSA.generate(2048)
    print("OK")
    key = []
    key.append(keyObject.publickey().export_key())
    key.append(keyObject.export_key(passphrase=pwd))
    return key


def encrypt(stream):
    '''
        Nombre: encrypt
        Descripcion: Encripta con AES con modo de encadenamiento CBC, con IV de 16 bytes, y longitud de clave de 256 bits.
        Argumentos:
            stream: Mensaje a encriptar en bytes
        Retorno:
            Diccionario con los valores "iv"(vector de inicializacion), "ciphertext"(mensaje cifrado) y "key"(clave simétrica usada para encriptar).
    '''

    iv = get_random_bytes(16)
    key_bytes = get_random_bytes(32)
    cipher = AES.new(key_bytes, AES.MODE_CBC,iv)
    ciphertext_bytes = cipher.encrypt(pad(stream, AES.block_size))

    return {'iv':iv, 'ciphertext':ciphertext_bytes, 'key':key_bytes}

def encrypt_with_password(stream,password):
    '''
        Nombre: encrypt_password
        Descripcion: Encripta con AES con modo de encadenamiento CBC, con IV de 16 bytes, y password introducida por usuario.
        Argumentos:
            stream: Mensaje a encriptar en bytes
            password: Password con la que se encripta
        Retorno:
            Diccionario con los valores "iv"(vector de inicializacion), "ciphertext"(mensaje cifrado) y "key"(clave simétrica usada para encriptar).
    '''

    iv = get_random_bytes(16)
    key_bytes = SHA256.new(password.encode()).digest()
    cipher = AES.new(key_bytes, AES.MODE_CBC,iv)
    ciphertext_bytes = cipher.encrypt(pad(stream, AES.block_size))

    return {'iv':iv, 'ciphertext':ciphertext_bytes, 'key':key_bytes}

def decrypt_with_password(stream,password,iv,signed):
    '''
        Nombre: decrypt_with_password
        Descripcion: Desencripta un mensaje encriptado con AES con modo de encadenamiento CBC, con IV de 16 bytes, y password introducida por usuario.
        Argumentos:
            stream: Mensaje a desencriptar con AES.
            password: Contraseña usada para desencriptar.
            iv: Vector de inicializacion que usa AES en modo CBC.
            signed: True si el mensaje lleva firma, False si no esta firmado.
        Retorno:
            El stream desencriptado o None en caso de error.
    '''

    return decrypt(stream,SHA256.new(password.encode()).digest(),iv,signed)

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
            El stream desencriptado o None en caso de error.
    '''
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
    except:
        print("Error al generar el cifrador AES con la llave simétrica e IV introducidos. Puede deberse a que el fichero solicitado no esté destinado a este usuario o la contraseña introducida sea incorrecta.")
        return None
    
    try:
        pt = unpad(cipher.decrypt(stream), AES.block_size)
    except:
        print("Error descifrando: tras descifrar, no hay paddings donde se esperaban. Puede deberse a un descifrado incorrecto dado que el fichero solicitado no esté destinado a este usuario o la contraseña introducida es incorrecta.")
        return None

    if(signed):
        return(pt[256:],pt[:256])
    return pt


def sign(stream,privKey,password):
    '''
        Nombre: sign
        Descripcion: Devuelve el mensaje firmado con una clave privada.
        Argumentos:
            stream: Mensaje a encriptar.
            privKey: Llave privada del emisor usada para firmar.
            password: Contraseña para importar la llave privada.
        Retorno:
            El mensaje con la firma concatenada delante. 
    '''

    #Calculamos el sha256 del mensaje
    hashedStream = SHA256.new(data = stream)

    # Generamos la firma
    if(password == None):
        firma = pkcs1_15.new(RSA.import_key(privKey)).sign(hashedStream)
    else:
        firma = pkcs1_15.new(RSA.import_key(privKey,passphrase=password)).sign(hashedStream)

    #Devolvemos la firma concatenada
    return firma + stream

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

    #Calculamos el sha256 del mensaje
    hashedStream = SHA256.new(data = stream)

    #Comprobamos la autenticidad del mensaje
    try:
        pkcs1_15.new(RSA.import_key(pubKey)).verify(hashedStream, firma)
        #print("The signature is valid.")
        return True
    except (ValueError, TypeError):
        #print("The signature is not valid.")
        return False


def enc_sign(stream,privKey,pubKey,password,firma=True):
    '''
        Nombre: enc_sign
        Descripcion: Aplicamos un mensaje híbrido para (firmar) y encriptar: (firma un mensaje usando RSA), encripta el mensaje firmado usando AES y luego genera un sobre digital con la clave simetrica.
        Argumentos:
            stream: Mensaje a firmar y encriptar
            privKey: clave privada del emisor usada para la firma digital.
            pubKey: clave publica del receptor usada para generar el sobredigital.
            firma: Indica si es necesario firmar el fichero.
            password: Contraseña para importar la llave privada.
        Retorno:
            Devuelve un string con los 16 primeros bytes el IV usado, los siguientes 32 bytes la clave simetrica usada, y los últimos el mensaje firmado y cifrado.
    '''

    #Firmamos
    if(firma): 
        streamFirmado = sign(stream,privKey,password)
    else:
        streamFirmado = stream

    #Encriptamos el mensaje firmado
    encrypted = encrypt(streamFirmado)

    #Generamos el sobre digital
    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(pubKey))
    sobreDigital = cipher_rsa.encrypt(encrypted["key"])
     
    return encrypted["iv"] + sobreDigital + encrypted["ciphertext"]

def dec_sign(stream,privKey,pubKey,password):
    '''
        Nombre: dec_sign
        Descripcion: Desencripta el mensaje encriptado en enc_sign y verifica su autenticidad.
        Argumentos:
            stream: Mensaje a desencriptar y verificar su autenticidad
            privKey: Llave privada del receptor para desencriptar el sobre digital
            pubKey: Llave publica del emisor usada para verificar la autenticidad del mensaje
            password: Contraseña para importar la llave privada.
        Retorno:
            Devuelve el mensaje descifrado y None si la signature no es valida o se da un error al desencriptar.
    '''

    iv = stream[:16]
    claveCifrada = stream[16:16 + 256]
    mensajeCifrado = stream[16 + 256:]

    if(password == None):
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(privKey))
    else:
        cipher_rsa = PKCS1_OAEP.new(RSA.import_key(privKey,passphrase=password))

    try:
        claveSimetrica = cipher_rsa.decrypt(claveCifrada)
    except ValueError:
        print("Error descifrando: Este mensaje no ha sido cifrado con su clave pública, es decir, usted no es el destinatario. Imposible descifrar.")
        return None

    #Desciframos el mensaje
    print("-> Descifrando fichero... ",end='')
    mensajeDescifrado = decrypt(mensajeCifrado, claveSimetrica, iv,True)
    if(mensajeDescifrado == None):
        return None
    print("OK")

    #Comprobamos la autenticidad del mensaje
    print("-> Verificando firma... ", end='')
    if(verify_sign(mensajeDescifrado[0], pubKey, mensajeDescifrado[1])):
        print("OK")
        return mensajeDescifrado[0]
    print("ERROR: Firma no válida")
    return None
