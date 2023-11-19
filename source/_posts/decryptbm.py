from pefile import PE
import struct
from aplib import decompress
import base64

file = "blackmatter.exe"

def zipcrypto_lcg(val,seed):
    newSeed = (0x8088405*seed + 1)&0xffffffff
    return ((newSeed*val)>>32)&0xffffffff,newSeed

def read_rsrc_section():
    pe = PE(file)
    sections = pe.sections
    for section in sections:
        if b".rsrc" in section.Name:
            desiredSection = section
            break
    return desiredSection.get_data()

def get_dwords_from_byte_buffer(byteBuffer):
    dwordsBuf = []
    for i in range(0,len(byteBuffer)-4,4):
        data = byteBuffer[i:i+4]
        dwordsBuf.append(int.from_bytes(data,"little"))
    return dwordsBuf

def generate_key(seed,bufLen):
    key = b''
    newSeed = seed
    for i in range(0,bufLen,4):
        value,newSeed = zipcrypto_lcg(seed,newSeed)
        key += struct.pack("<I",value)
    return key

def decrypt_buffer(buffer,keystream,size):
    decrypted = []
    for i in range(size):
        decrypted.append(buffer[i]^keystream[i])        
    return bytes(decrypted)

def decode_config(config):
    b64strings = config.split(b"\x00")
    configItems = []
    for b64string in b64strings:
        try:
            data = base64.b64decode(b64string)
            items = data.split(b'\x00\x00')
            items = [item.replace(b'\x00',b'') for item in items]
            for item in items:
                try:
                    decodedData = item.decode("utf-8")
                    if len(decodedData)!=0:
                        configItems.append(decodedData)
                except Exception:
                    pass
        except Exception:
            pass
    return configItems

dwordsBuf = get_dwords_from_byte_buffer(read_rsrc_section())
encData = read_rsrc_section()[8:]
seed = dwordsBuf[0]
print(seed)
bufLen = dwordsBuf[1]
key = generate_key(seed,bufLen)
decryptedBlob = decrypt_buffer(encData,key,bufLen)
decompressedData = decompress(decryptedBlob)
base64Blobs = decompressedData[204:]
configData = decode_config(base64Blobs)
print(configData)