---
title: Reversing Conti Ransomware
date: 2022-12-25
tags: [ransomware, malware]
---

## Overview

`Packed Sample` : [https://bazaar.abuse.ch/sample/03b9c7a3b73f15dfc2dcb0b74f3e971fdda7d1d1e2010c6d1861043f90a2fecd/](https://bazaar.abuse.ch/sample/03b9c7a3b73f15dfc2dcb0b74f3e971fdda7d1d1e2010c6d1861043f90a2fecd/)

`Unpacked Sample` : [https://bazaar.abuse.ch/sample/d3c75c5bc4ae087d547bd722bd84478ee6baf8c3355b930f26cc19777cd39d4c/](https://bazaar.abuse.ch/sample/d3c75c5bc4ae087d547bd722bd84478ee6baf8c3355b930f26cc19777cd39d4c/)

`MD5` : B3D6BA0AA663F699283D25DDCB6561B9

`SHA 256`: D3C75C5BC4AE087D547BD722BD84478EE6BAF8C3355B930F26CC19777CD39D4C

This post deals with the unpacked sample. 

## Basic Static Analysis

* According to PE Bear as well as IDA, the ransomware imports three DLLs namely `kernel32.dll`, `USER32.dll` and `WS2_32.dll`.

* Interesting data found by extracting strings from the executable
```
Our website
TOR VERSION : 
(you should download and install TOR browser first https://torproject.org) 
http://m232fdxbfmbrcehbrj5iayknxnggf6niqfj6x4iedrgtab4qupzjlaid.onion 
HTTPS VERSION : 
contirecovery.best
YOU SHOULD BE AWARE! 
Just in case, if you try to ignore us. We've downloaded you
---BEGIN ID---
sRttGzzkzsoiC9s8LgcrQk64ew7H47a5JSjCsLGbwdijogjulfu3RO9XBJbfEgCZ
---END ID---
.CECJF
RSA1
```

- This reveals the name of the malware `A:\source\conti_v3\Release\cryptor.pdb`

## Advanced Static Analysis

### String Decryption
Analysing the function `sub_401010` in IDA, we notice some stack strings and their corresponding decryption loop. We can extract those strings and write a decryptor.

```py
enc_s_1 = [1,16,47,57,16,62,14,80 ,90 ,82 ,62, 62, 78]
enc_s_2 = [104, 84, 13 ,111,18,13,120,9,49,49,17]
enc_s_3 = [15,6,5,112,90,41,44,37,9,6,0x3e,0x3e]
enc_s_4 = [11,22,35,92,92,63,35,92,92,21]
enc_s_5 = [39,85,71,99,71,42,126,99,35,41,56,56,44]
enc_s_6 = [96,115,71,47,77,70,101,115,115,53]
enc_s_7 = [101,97,6,46,87,74,118,105,53,120,97,97,90]
enc_s_8 = [50,78,30,40,119,116,111,38,0,5,81,81,71]
enc_s_9 = [90,123,126,61,123,81,123,78,116,64,61,61,38]
enc_s_10 = [73,77,108,98,118,12,53,72,46,108,108,33]
enc_s_11 = [81,92,36,82,82,34,100,110,102,82,82,98]
enc_s_12 = [92,100,125,88,100,6,82,41,4,59,6,6,23]
enc_s_13 = [38,113,11,113,113,113]

def decrypt_string_1(buffer,flag,k1,k2):
	if flag == -1:
		for i in range(len(buffer)):
			print(chr((k1 * (buffer[i] - k2) % 127 + 127) % 127),end='')
	else:
		for i in range(len(buffer)):
			print(chr((k1 * (k2-buffer[i]) % 127 + 127) % 127),end='')
	print()

decrypt_string_1(enc_s_1,-1,25,78)
decrypt_string_1(enc_s_2,-1,51,17)
decrypt_string_1(enc_s_3,1,18,68)
decrypt_string_1(enc_s_4,1,11,21)
decrypt_string_1(enc_s_5,-1,9,44)
decrypt_string_1(enc_s_6,-1,55,53)
decrypt_string_1(enc_s_7,1,39,90)
decrypt_string_1(enc_s_8,1,40,71)
decrypt_string_1(enc_s_9,1,45,38)
decrypt_string_1(enc_s_10,-1,37,33)
decrypt_string_1(enc_s_11,-1,25,98)
decrypt_string_1(enc_s_12,-1,31,23)
```

Running this script gives us the names of some DLLs. However, PE Bear was able to detect only three DLLs. This means that the program might be loading these DLLs manually using some API function.
```
λ python decryptor.py
kernel32.dll
ws2_32.dll
Advapi32.dll
ntdll.dll
Rstrtmgr.dll
Ole32.dll
OleAut32.dll
Netapi32.dll
Iphlpapi.dll
Shlwapi.dll
Shell32.dll
```
After decrypting the dll names, the malware calls `sub_955650(15, 0xBE3D21A8, 107)`, and calls the pointer returned by it with the first argument as a pointer to the dll name. Please note that the function name may be different in different instances of the program.

```
v26 = sub_951B80((unsigned __int8 *)v45);
v27 = (int (__stdcall *)(unsigned __int8 *))sub_955650(15, 0xBE3D21A8, 107);
v28 = v27(v26);
```
Stepping into this function call using dynamic analysis, we find that this call is nothing but a call to `LoadLibraryA` with the first argument as the dll name. 

This means that the call `sub_955650(15, 0xBE3D21A8, 107)` returns a pointer to `LoadLibraryA` which is eventually called with the first argument as the decrypted dll name, subsequently returning a handle to the particular dll. Further, handles to the DLLs are passed to the function `sub_951730` which calls `sub_955650` with some different arguments. First of all, let's find out some of the functions that are returned by subsequent calls to `sub_955650`. I've renamed this function to `mw_resolve_api`.

```cpp
mw_resolve_api(15, 0xBE3D21A8, 107) -> LoadLibraryA
mw_resolve_api(15, 0x5FA07416, 103) -> GetModuleFileNameW
mw_resolve_api(15, 0xF06E87CA, 12)  -> CreateFileW
mw_resolve_api(15, 0x1B1ACBCC, 5)   -> GetFileSizeEx
mw_resolve_api(15, 0x269E9EF4, 104) -> CreateFileMappingW
mw_resolve_api(15, 0xB9072E66, 105) -> MapViewOfFile
mw_resolve_api(15, 0x92F9234B, 108) -> GetProcAddress
mw_resolve_api(15, 0xD52132A3, 24)  -> GetCommandLineW
mw_resolve_api(23, 0xC7DFA7FC, 61)  -> CommandLineToArgvW
mw_resolve_api(15, 0xF701962C, 25)  -> CreateMutexA
mw_resolve_api(15, 0x6A095E21, 11)  -> WaitForSingleObject
mw_resolve_api(15, 0xDF1AF05E, 19)  -> GetNativeSystemInfo
mw_resolve_api(15, 0x3A4532BE, 27)  -> CreateThread
mw_resolve_api(16, 0x5CC1CCBC, 57)  -> CryptAcquireContextA
mw_resolve_api(16, 0xA247FF77, 54)  -> CryptImportKey
mw_resolve_api(15, 0x21CCA665, 33)  -> RtlEnterCriticalSection
mw_resolve_api(15, 0xF99EABB9, 35)  -> RtlLeaveCriticalSection
mw_resolve_api(15, 0x1D7AB241, 51)  -> WaitForMultipleObjects
mw_resolve_api(15, 0xE4B69F3B, 40)  -> Sleep
mw_resolve_api(15, 0xD72E57A9, 28)  -> lstrcmpiW
mw_resolve_api(15, 0xF06E87CA, 12) -> CreateFileW
mw_resolve_api(15, 0xC65C5EE6, 3) -> lstrlen
mw_resolve_api(15, 0xC45F4A8C, 7) -> WriteFile
mw_resolve_api(15, 0xA5EB6E47, 18) -> CloseHandle
mw_resolve_api(15, 0xE2B40F85, 46) -> FindFirstFileW
mw_resolve_api(15, 0x397B11DF, 49) -> lstrcmpW
mw_resolve_api(15, 0x9AEA18E1, 47) -> FindNextFileW
mw_resolve_api(22, 0x5A8CE5B8, 74) -> shlwapi_StrStrIW
mw_resolve_api(16, 0xABCB0A67, 56) -> CryptGenRandom
mw_resolve_api(16, 0x6C6C937B, 55) -> CryptEncrypt
mw_resolve_api(15, 0x93AFB23A, 13) -> GetFileAttributesW
mw_resolve_api(15, 0x1FBBB84F, 16) -> GetLastError
mw_resolve_api(15, 0x1B1ACBCC, 5) -> GetFileSizeEx
mw_resolve_api(15, 0x4D9702D0, 22) -> lstrcpyW
mw_resolve_api(15, 0x7BA2639, 17) -> lstrcatW
mw_resolve_api(15, 0xC8FB7817, 23) -> MoveFileW

```

### Command Line Arguments
Decrypting enc_s_13 by calling `decrypt_string_1(enc_s_13,1,26,113)` gives `- p` which is possibly a command line argument. The function `sub_11A7810(char*)` parses various command line arguments. Let's find out the possible values.

```py
cmd_enc_1 = [38,113,11,113,113,113]
cmd_enc_2 = [103,10,49,10,10,10]
cmd_enc_3 = [38,19,90,19,32,19,102,19,19,19]
cmd_enc_4 = [86,56,48,56,126,56,95,56,81,56,56,56]
cmd_enc_5 = [24,37,104,37,115,37,93,37,54,37,43,37,5,37,87,37,37,37]
cmd_enc_6 = [43,4,16,4,16,4,4,4]
cmd_enc_7 = [44,125,10,125,19,125,84,125,44,125,125,125]
cmd_enc_8 = [125,64,105,64,96,64,64,64]
cmd_enc_9 = [49,115,73,115,25,115,87,115,101,115,94,115,22,115,115,115]

decrypt_string_1(cmd_enc_1,1,26,113)
decrypt_string_1(cmd_enc_2,1,20,10)
decrypt_string_1(cmd_enc_3,1,11,19)
decrypt_string_1(cmd_enc_4,1,62,56)
decrypt_string_1(cmd_enc_5,1,23,37)
decrypt_string_1(cmd_enc_6,-1,9,4)
decrypt_string_1(cmd_enc_7,-1,41,125)
decrypt_string_1(cmd_enc_8,1,44,64)
decrypt_string_1(cmd_enc_9,-1,37,115)
```
Running this script gives the following output:
```
- p
- m
- l o g
- s i z e
- n o m u t e x
a l l
l o c a l
n e t
b a c k u p s
```
Conti can only be ran with command-line arguments, so there must be a loader for supplying appropriate command line arguments and launching the malware. Further investigation yields the following setup:

<table>
	<thead>
		<th>Argument</th>
		<th>Functionality</th>
	</thead>
	<tbody>
		<tr>
			<td>-nomutex</td>
			<td>Do not use mutex</td>
		</tr>
		<tr>
			<td>-p dir_path</td>
			<td>Encrypt all the files in a directory whose path is given by dir_path</td>
		</tr>
	</tbody>
</table>

Let's analyze each command line argument, one by one

1. `-p dir_path`

![](/images/conti/img_1.png)

`mw_wrap_RtlInitializeCriticalSection(0, 1)` initializes a critical section and `mw_wrap_CreateThread(0)`spawns a number of threads. In this case (when you use the -p flag), only 1 thread is spawned by the malware. I've renamed the function executed by the thread to `mw_fn_thread_1`. It calls a function `sub_1AB520(&var_cryptoPov)` which initially inserts some characters into a buffer. I've renamed the buffer to `var_crypt_provider`, and after that performs a string decryption.

![](/images/conti/img_2.png)

```py
enc_sth = b"\x11NJTR\x00RL+r6'#s'J!uri\x15\trs'ur\t6\x15r_T\x04}+RwTs}#NJr\x13TR\x02Nu!T\x08"
decrypt_string_1(enc_sth,1,62,8)
```
This gives `Microsoft Enhanced RSA and AES Cryptographic Provider`. This Cryptographic service provider supports various algorithms such as Triple DES, AES 128, AES 192, MAC,etc. For more information, check [this](https://learn.microsoft.com/en-us/windows/win32/seccertenroll/cryptoapi-cryptographic-service-providers). After that, the malware calls `CryptAcquireContextA(arg_phProv, 0, var_crypt_provider, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)`. If it succeeds, the function returns, otherwise it sets up a new buffer, decrypts it to get the provider `Microsoft Enhanced RSA and AES Cryptographic Provider` and calls `CryptAcquireContextA` again. If it fails, the malware again sets up a buffer, decrypts it and calls `CryptAcquireContextA`. This entire thing can be done at most 4 times.
After that, the malware calls `CryptImportKey` with the second argument as a global buffer which might be a public RSA key. 

![](/images/conti/img_3.png)
Following different functions over here, we ultimately get something interesting.

![](/images/conti/img_4.png)
Let's decrypt the blob of code as seen in the image above.
```py
enc_sth_5 = b'\x10}"}\x14}^}>}"} }\x17}%}\x17}}'
decrypt_string_1(enc_sth_5,1,36,125)
```
This gives us the output `r e a d m e . t x t`. If you run the malware standalone, with the `-p` flag, you'll notice that the decryption instructions are stored in this file.

![](/images/conti/img_5.png)

The malware creates a file `readme.txt` in the directory supplied as a command line argument, and writes the data stored in a global buffer into it. 

![](/images/conti/img_6.png)

