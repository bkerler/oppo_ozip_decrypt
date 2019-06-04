#!/usr/bin/env python3
# (c) B.Kerler, MIT license
import os
import sys
from struct import unpack
from struct import unpack

if len(sys.argv)<2:
    print("Usage: ./ofp_libextract.py [Filename.ofp]")
    exit(0)

filename=sys.argv[1]
filesize=os.stat(filename).st_size

def elfcalcsize(pos):
    rf.seek(pos)
    data=rf.read(0x200)
    if data[:4]!=b"\x7FELF":
        print("No ELF detected.")
        return 0
    sectionheaderoffset=unpack("<I",data[0x20:0x24])[0]
    sectionentrysize=unpack("<H",data[0x2C:0x2E])[0]
    sectionentries = unpack("<H", data[0x30:0x32])[0]
    filesize=sectionheaderoffset+(sectionentries*sectionentrysize)
    return filesize

def reverseseekforelf(rf,idx):
    pos=idx-0x20000
    area=[]
    while(pos>0):
        rf.seek(pos)
        data=rf.read(0x20004)
        idx=data.find(b"\x7FELF")
        if idx!=-1:
            length=elfcalcsize(pos+idx)
            if length>0x50000 and length<0x200000:
                return [(pos+idx),length]
            if length>0x200000:
                return []
        pos-=0x20000
    return []

def seekfordecryptstring(rf):
    pos=0
    area=[]
    old=0
    i=0
    while(pos<filesize):
        rf.seek(pos)
        percent=int(pos/filesize*100)
        if percent>old:
            old=percent
            print(f"{percent}% scanned.")
        data=rf.read(0x20004)
        idx=data.find(b"OPPOENCRYPT!\x00Decrypt failed!")
        if idx!=-1:
            print(f"Found a possible candidate at: {hex(dinfo[0])}")
            dinfo=reverseseekforelf(rf,pos+idx)
            if dinfo!=[]:
                i += 1
                print(f"Extracting possible candidate: {hex(dinfo[0])}, Length:{hex(dinfo[1])} as {str(i)}.elf")
                rf.seek(dinfo[0])
                data=rf.read(dinfo[1])
                with open(f"{str(i)}.elf","wb") as wf:
                    wf.write(data)
        pos+=0x20000
    return area


def seekforrecovery(rf):
    pos=0
    area=[]
    old=0
    i=0
    found=0
    while(pos<filesize):
        rf.seek(pos)
        percent=int(pos/filesize*100)
        if percent>old:
            old=percent
            print(f"{percent}% scanned.")
        data=rf.read(0x20004)
        idx=0
        idx=data.find(b"\x1F\x8B\x08\x00\x00\x00\x00\x00\x00",idx)
        if idx!=-1:
            found+=1
            if found>1:
                print(f"Found a possible candidate at: {hex(pos+idx)}")
                pos=pos+idx
                pos2=pos
                while(pos2<filesize):
                    rf.seek(pos2)
                    percent=int(pos2/filesize*100)
                    if percent>old:
                        old=percent
                        print(f"{percent}% scanned.")
                    data=rf.read(0x20004)
                    idx2=data.find(b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
                    if idx2!=-1:
                        print(f"Extracting recovery: {hex(pos)}, Length:{hex(pos2+idx2-pos)} as recovery.cpio.gz")
                        rf.seek(pos)
                        data=rf.read(pos2+idx2-pos)
                        with open(f"recovery{str(found-1)}.cpio.gz","wb") as wf:
                            wf.write(data)
                        break;
                    pos2+=0x20000
        pos+=0x20000
    return area

with open(filename,'rb') as rf:
    #info=seekfordecryptstring(rf)
    seekforrecovery(rf)
    print("Done.")
