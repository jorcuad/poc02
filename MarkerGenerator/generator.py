#!/usr/bin/python
import sys
from ecdsa import SigningKey
import argparse
from PyPDF2 import PdfFileReader
from Crypto.Cipher import AES
import qrcode
import base64
import random
from Crypto import Random

def main(document_path, certificate_path=None):
    logger("================ INITIALICING ================")
    if(not certificate_path):
        logger("NIST192p PEM not provided.")
        createKeys()
        logger("Creating NIST192p PEM. Stored in the script folder.")
        certificate_path = "private.pem"

    logger("================ GETTING FILE HMAC ================")
    hmac_content = getFileHMAC(document_path, certificate_path)
    data = '{ "content":"' + str(hmac_content) + '",'
    logger("FILE HMAC SIGNATURE: " + str(hmac_content))

    logger("================ GETTING METADATA ================")
    metadata = getFileMetadata(document_path)
    logger(metadata)

    logger("================ GETTING METADATA HMAC ================")
    hmac_metadata = getMessageHMAC(str.encode(metadata))
    data += '"metadata":"' + str(hmac_metadata) + '",'
    logger(hmac_metadata)

    logger("================ OWNERSHIP ================")
    owner = ""
    if(args.owner):
        logger("SETTING OWNER: " + args.owner)
        data += '"owner":"' + args.owner + '",'
    else:
        logger("NO OWNER SETTED.")

    logger("================ SENSIBILITY LEVEL ================")
    if(args.sensibility_level):
        logger("Setting sensibility level: " + args.sensibility_level)
        data += '"sensibilityLevel":' + args.sensibility_level + '",'
    else:
        logger("No sensibility level selected, default is: Public.")
        data += '"sensibilityLevel":"public"}'

    logger("================ Ciphering Information ================")
    logger("DATA: " + data)
    ciphertext = encrypt(data, args.cipherkey)
    logger("CIPHERTEXT: ")
    logger(ciphertext)

    logger("================ Creating QRCode ================")
    createQR(ciphertext)
    logger("QR Code image created in the project folder.")

def getFileMetadata(document_path):
    with open(document_path, 'rb') as f:
        pdf = PdfFileReader(f)
        info = pdf.getDocumentInfo()
        number_of_pages = pdf.getNumPages()
        keys = info.keys()
        concatenatedKeys = ""
        for key in keys:
            concatenatedKeys += key + ":" + pdf.getObject(info.get(key)) + ";"
        return concatenatedKeys

def createQR(ciphertext):
    imagen = qrcode.make(ciphertext)
    qrname = "cipherQR.png"
    if(args.qrname):
        qrname = args.qrname
    archivo_imagen = open(qrname, 'wb')
    imagen.save(archivo_imagen)
    archivo_imagen.close()

def pad(data):
    length = 16 - (len(data) % 16)
    return data + chr(length)*length

def unpad(data):
    return data[:-ord(data[-1])]

def encrypt(message, passphrase):
    BLOCK_SIZE = 16
    IV = Random.new().read(BLOCK_SIZE)
    aes = AES.new(str.encode(passphrase), AES.MODE_CFB, IV, segment_size=128)
    b64IV = base64.b64encode(IV).decode('utf-8')
    logger("IV: " + b64IV)
    b64CT = base64.b64encode(IV + aes.encrypt(pad(message).encode('utf8'))).decode('utf-8')
    return b64CT

def decrypt(encrypted, passphrase):
    BLOCK_SIZE = 16
    encrypted = base64.b64decode(encrypted)
    IV = encrypted[:BLOCK_SIZE]
    aes = AES.new(passphrase, AES.MODE_CFB, IV, segment_size=128)
    return unpad(aes.decrypt(encrypted[BLOCK_SIZE:]))

def createKeys():
    sk = SigningKey.generate()
    vk = sk.verifying_key
    with open("private.pem", "wb") as f:
        f.write(sk.to_pem())
    with open("public.pem", "wb") as f:
        f.write(vk.to_pem())

def getFileHMAC(document_path, certificate_path):
    with open(certificate_path) as f:
        sk = SigningKey.from_pem(f.read())
    with open(document_path, "rb") as f:
        message = f.read()
    sig = sk.sign(message)
    return base64.b64encode(sig).decode("utf-8")

def getMessageHMAC(strMessage):
    with open("private.pem") as f:
        sk = SigningKey.from_pem(f.read())
    message = strMessage
    sig = sk.sign(message)
    return base64.b64encode(sig).decode("utf-8")

def getFileBinaryRepresentation(document_path):
    bytetable = [("00000000"+bin(x)[2:])[-8:] for x in range(256)]
    binrep = "".join(bytetable[x] for x in open(document_path, "rb").read())
    return binrep

def logger(message):
    if(args.verbosity):
        print(message)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate the ciphered content of a QR for a AR verification library.')
    parser.add_argument("-v", "--verbosity", help="increase output verbosity.", action="store_true")
    parser.add_argument("-c", "--certificate_path", type=str, help="[OPTIONAL] Path to private NIST192p curve certificate.")
    parser.add_argument("-d", "--document_path", type=str, help="[MANDATORY] Path to private NIST192p curve certificate.",  required=True)
    parser.add_argument("-k", "--cipherkey", type=str, help="[MANDATORY] Key to cipher the QR data.",  required=True)
    parser.add_argument("-s", "--sensibility_level", type=str, help="[OPTIONAL] Set a level of sensibility: Private, Reserved, Public.")
    parser.add_argument("-o", "--owner", type=str, help="[OPTIONAL] The one who received this file.")
    parser.add_argument("-q", "--qrname", type=str, help="[OPTIONAL] The name of the qr file generated.")
    args = parser.parse_args()

    if(args.certificate_path):
        main(args.document_path, args.certificate_path)
    else:
        main(args.document_path)
