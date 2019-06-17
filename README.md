# oppo_decrypt_ozip
Oppo/Oneplus .ozip Firmware decrypter
------------------------------------

Tested with CPH1707EX, CPH1611EX OTA Zip and Python 3.6

* ozipdecrypt.py : Decrypt Oppo .ozip to .zip
* decrypt.py  : Decrypts any part of the firmware

Based on python 3.6

Prerequirement:
-------------
'pip3 install pycrypto' or
'pip3 install pycryptodome'


Usage:
-------- 
* OTA OZIP decryption:
'python3 ozipdecrypt.py CPH1707EX_OTA_0070_all.ozip'

* OTA Boot.img decryption:
'python3 ozipdecrypt.py boot.img'

File will be decrypted as *.zip or boot.img.dec

License:
-------- 
Share, modify and use as you like, but refer the original author !

Tutorial:
---------
For a tutorial on aes key extraction, head over [here](https://bkerler.github.io/reversing/2019/04/24/the-game-begins/).

For extraction of libpatchapply.so or /sbin/recovery, use:
'./ofp_libextract.y [your_ofp_file]'
If you're getting a recovery.cpio.7z file, extract using 7z to get the /sbin/recovery file.
