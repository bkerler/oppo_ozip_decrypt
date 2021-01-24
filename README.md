# oppo_decrypt_ozip
Oppo/Oneplus .ozip Firmware decrypter
------------------------------------

Tested with CPH1707EX, CPH1611EX OTA Zip and Python >= 3.6

* ozipdecrypt.py : Decrypt Oppo .ozip to .zip

Prerequirement:
-------------
```
sudo apt install python3-pip
pip3 install -r requirements.txt
```

Usage:
-------- 
* OTA OZIP decryption:

```
./ozipdecrypt.py CPH1707EX_OTA_0070_all.ozip
```

File will be decrypted as *.zip

License:
-------- 
Share, modify and use as you like, but refer the original author !

Tutorial:
---------
For a tutorial on aes key extraction, head over [here](https://bkerler.github.io/reversing/2019/04/24/the-game-begins/).

For extraction of libpatchapply.so or /sbin/recovery, use:

```
./ofp_libextract.py [your_ofp_file]
```

If you're getting a recovery.cpio.7z file, extract using 7z to get the /sbin/recovery file.
