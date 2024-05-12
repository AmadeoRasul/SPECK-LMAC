import speck
import binascii
import sys
import hashlib


mess = input("message: ")
k = input("key: ")


def getBinary(word):
    return int(binascii.hexlify(word), 16)

if (len(sys.argv)>1):
	mess=str(sys.argv[1])
	m=getBinary(mess)

if (len(sys.argv)>2):
	k=str(sys.argv[2])

key=int(k,16)


print ("Message:\t",mess)
print ("Key:\t\t",k)

ksize=(len(k)-2)*4

bsize=32
if (ksize==72): bsize=48
if (ksize==96): bsize=48
if (ksize==128): bsize=64

print ("Key size:\t",ksize)
print ("Block size:\t",bsize)

w = speck.SpeckCipher(key, key_size=ksize, block_size=bsize)
t = w.encrypt(int.from_bytes(mess.encode(), byteorder='big'))

def lightMac_sha256(input_string):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string.encode('utf-8'))
    return sha256_hash.hexdigest()

mac = (k)
tag = lightMac_sha256(mac)

print ("Encrypted:\t",hex(t))
print ("Key for LightMac Encryption:\t",mac)
print ("LightMAC Tag:\t",tag)


res = w.decrypt(t)

hexstr= hex(res)
print ("Decrypt:\t",hexstr)

res_str=bytes.fromhex(hexstr[2:]).decode('utf-8')
print ("Decrypt:\t",res_str)
