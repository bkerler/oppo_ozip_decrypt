import os
import sys
import binascii
from Crypto.Cipher import AES

keys=[
        "2143DCCB21513E39E1DCAFD41ACEDBD7",
        "2D23CCBBA1563519CE23C1C4AA1E3412",
        "1E38C1B72D522E29E0D4ACD50ACFDCD6",
        "D6DCCF0AD5ACD4E0292E522DB7C1381E"
      ]

def keytest(data):
    for key in keys:
        ctx=AES.new(binascii.unhexlify(key),AES.MODE_ECB)
        dat=ctx.decrypt(data)
        if (dat[0:4]==b'\x50\x4B\x03\x04'):
            print ("Found correct AES key: "+key)
            return binascii.unhexlify(key)
    return -1

def main():
    print ("ozipdecrypt 0.1 (c) B.Kerler 2017")
    if (len(sys.argv)!=2):
        print ("usage: ozipdecrypt.py [*.ozip]")
        exit(1)

    with open(sys.argv[1],'rb') as fr:
        magic=fr.read(12).decode()
        if (magic!="OPPOENCRYPT!"):
            print ("ozip has unknown magic, OPPOENCRYPT! expected !")
            exit(1)
        fr.seek(0x1050)
        data=fr.read(16)
        key=keytest(data)
        if (key==-1):
            print("Unknown AES key, reverse key from recovery first!")
            exit(1)
        with open(sys.argv[1][:-4]+"zip",'wb') as wf:
            fr.seek(0x1050)
            ctx = AES.new(key, AES.MODE_ECB)
            while (True):
                data=fr.read(16)
                if len(data)==0:
                    break
                wf.write(ctx.decrypt(data))
                data = fr.read(0x4000)
                if len(data)==0:
                    break
                wf.write(data)

if __name__ == '__main__':
    main()