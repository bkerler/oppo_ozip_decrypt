#!/usr/bin/env python3
#(c) B. Kerler 2017-2018, licensed under MIT license

import os
import sys
import binascii
from Crypto.Cipher import AES

keys=[
        "2143DCCB21513E39E1DCAFD41ACEDBD7",
        "2D23CCBBA1563519CE23C1C4AA1E3412", #A77
        "1E38C1B72D522E29E0D4ACD50ACFDCD6",
        "D7DBCE1AD4AFDCE1393E5121CBDC4321", #R11s, Plus
        "D6DCCF0AD5ACD4E0292E522DB7C1381E", #R9s, Plus, R11
        "12341EAAC4C123CE193556A1BBCC232D",
        "D4D2CD61D4AFDCE13B5E01221BD14D20", #FindX
        "261CC7131D7C1481294E532DB752381E", #FindX
        "172B3E14E46F3CE13E2B5121CBDC4321", #Realme 1
      ]

def aes_dec(key,data):
    ctx=AES.new(binascii.unhexlify(key),AES.MODE_ECB)
    return ctx.decrypt(data)

def keytest(data):
    for key in keys:
        dat=aes_dec(key,data)
        if (dat[0:4]==b'\x50\x4B\x03\x04'):
            print ("Found correct AES key: "+key)
            return key
    return -1

def main():
    print ("ozipdecrypt 0.2 (c) B.Kerler 2017-2018")
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
            print("Decrypting...")
            while (True):
                data=fr.read(16)
                if len(data)==0:
                    break
                wf.write(aes_dec(key,data))
                data = fr.read(0x4000)
                if len(data)==0:
                    break
                wf.write(data)
            print("DONE!!")

if __name__ == '__main__':
    main()
