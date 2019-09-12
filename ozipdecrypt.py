#!/usr/bin/env python3
#(c) B. Kerler 2017-2019, licensed under MIT license

import os
import sys, stat
import shutil
import binascii
from Crypto.Cipher import AES
from zipfile import ZipFile

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
        "1CA21E12271335AE33AB81B2A7B14622", #Realme 2 pro
        "acaa1e12a71431ce4a1b21bba1c1c6a2", #Realme U1 RMX1831
        "acac1e13a72531ae4a1b22bb31c1cc22", #Realme 3 RMX1825EX
        "1c4c1ea3a12531ae491b21bb31613c11", #Realme 3 Pro, Realme X
        "D4D2CE11D4AFDCE13B3E0121CBD14D20", #K1
        "ACAC1E13A12531AE4A1B21BB31C13C21", #Reno
        "ACAC1E13A72431AE4A1B22BBA1C1C6A2", #A9
        "1c4c1ea3a12531ae4a1b21bb31c13c21", #Reno 10x zoom PCCM00
        "D6EECF0AE5ACD4E0E9FE522DE7CE381E", #mnkey
        "D6ECCF0AE5ACD4E0E92E522DE7C1381E", #mkey
        "D6DCCF0AD5ACD4E0292E522DB7C1381E", #realkey
        "D7DCCE1AD4AFDCE2393E5161CBDC4321", #testkey
        "D7DBCE2AD4ADDCE1393E5521CBDC4321", #utilkey
        "12cac11211aac3aea2658690122c1e81", #A1,A83t
        "2442CE821A4F352E33AE81B22BC1462E", #R17 Pro
      ]

   
def keytest(data):
    for key in keys:
        ctx=AES.new(binascii.unhexlify(key),AES.MODE_ECB)
        dat=ctx.decrypt(data)
        if (dat[0:4]==b'\x50\x4B\x03\x04'):
            print ("Found correct AES key: "+key)
            return binascii.unhexlify(key)
        elif (dat[0:4]==b'\x41\x4E\x44\x52'):
            print ("Found correct AES key: "+key)
            return binascii.unhexlify(key)
    return -1

def del_rw(action, name, exc):
    os.chmod(name, stat.S_IWRITE)
    os.remove(name)

def rmrf(path):
    if os.path.exists(path):
        if os.path.isfile(path):
            del_rw("",path,"")
        else:
            shutil.rmtree(path, onerror=del_rw)

def main():
    print ("ozipdecrypt 0.5 (c) B.Kerler 2017-2019")
    if (len(sys.argv)!=2):
        print ("usage: ozipdecrypt.py [*.ozip]")
        exit(1)

    with open(sys.argv[1],'rb') as fr:
        magic=fr.read(12)
        if (magic==b"OPPOENCRYPT!"):
                pk=False
        elif magic[:2]==b"PK":
                pk=True
        else:
                print ("ozip has unknown magic, OPPOENCRYPT! expected !")
                exit(1)
        
        if pk==False:
            fr.seek(0x1050)
            data=fr.read(16)
            key=keytest(data)
            if (key==-1):
                print("Unknown AES key, reverse key from recovery first!")
                exit(1)
            ctx=AES.new(key,AES.MODE_ECB)
            filename=sys.argv[1][:-4]+"zip"
            with open(filename,'wb') as wf:
                fr.seek(0x1050)
                print("Decrypting...")
                while (True):
                    data=fr.read(16)
                    if len(data)==0:
                        break
                    wf.write(ctx.decrypt(data))
                    data = fr.read(0x4000)
                    if len(data)==0:
                        break
                    wf.write(data)
            print("DONE!!")
        else:
            testkey=True
            with ZipFile(sys.argv[1],'r') as zipObj:
                if os.path.exists('temp'):
                    rmrf('temp')
                os.mkdir('temp')
                if os.path.exists('out'):
                    rmrf('out')
                os.mkdir('out')
                print("Extracting "+sys.argv[1])
                zipObj.extractall('temp')
                for r, d, f in os.walk('temp'):
                    for file in f:
                        rfilename=os.path.join(r, file)
                        wfilename = os.path.join("out", rfilename[rfilename.rfind('/') + 1:])
                        with open(rfilename,'rb') as rr:
                            magic = rr.read(12)
                            if (magic == b"OPPOENCRYPT!"):
                                if testkey==True:
                                    with open(os.path.join("temp","boot.img"),"rb") as rt:
                                        rt.seek(0x1050)
                                        data=rt.read(16)
                                        key=keytest(data)
                                        if (key==-1):
                                            print("Unknown AES key, reverse key from recovery first!")
                                            exit(1)
                                    testkey=False
                                with open(wfilename,'wb') as wf:
                                    rr.seek(0x10)
                                    dsize=int(rr.read(0x10).replace(b"\x00",b"").decode('utf-8'),10)
                                    rr.seek(0x1050)
                                    print("Decrypting "+rfilename)
                                    flen=os.stat(rfilename).st_size-0x1050

                                    ctx = AES.new(key, AES.MODE_ECB)
                                    while (dsize>0):
                                        if flen>0x4000:
                                            size=0x4000
                                        else:
                                            size=flen
                                        data = rr.read(size)
                                        if dsize<size:
                                            size=dsize
                                        if len(data)==0:
                                            break
                                        dr=ctx.decrypt(data)
                                        wf.write(dr[:size])
                                        flen-=size
                                        dsize-=size
                            else:
                                shutil.move(rfilename,wfilename)
                rmrf('temp')
                print("DONE ... files decrypted to the \"out\" directory !!")

if __name__ == '__main__':
    main()
