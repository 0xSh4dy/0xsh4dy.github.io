---
title: Reversing Blackmatter Ransomware
date: 2023-06-07
tags: [ransomware,malware]
---

By analyzing the executable using PE bear, it becomes evident that it solely imports three DLLs: `kernel32.dll`, `user32.dll`, and `gdi32.dll`.
This suggests that either the executable is packed or some technique has been employed to obfuscate the API calls. Upon opening the executable in IDA, we promptly identify the utilization of the API hashing technique.

### Resolving API Hashes
There are two functions available for hash computation. The first function calculates the hash of a DLL name, while the second function computes the hash from a function name. Not all hashes are the exact hashes of a dll or function.

![](/images/rev/bm/bm02.png)

![](/images/rev/bm/bm01.png)


![](/images/rev/bm/bm03.png)

![](/images/rev/bm/bm04.png)


It is important to note that not all the values in the array shown above represent the actual hashes of DLLs or functions. Many of these values result from performing an XOR operation between the original hash and a specific number. Now, let's write few python scripts to extract the function names associated with those hashes.
```py
# This script creates a list of the functions exported by various DLLs and saves them in exports.yaml

import pefile
import yaml

system32_path = "C:\\Windows\\System32\\"
dlls = [
    'ntdll.dll',
    'kernel32.dll',
    'user32.dll',
    'gdi32.dll',
    'advapi32.dll',
    'comctl32.dll',
    'shell32.dll',
    'ole32.dll',
    'oleaut32.dll',
    'msvcrt.dll',
    'wininet.dll',
    'winspool.drv',
    'ws2_32.dll',
    'netapi32.dll',
    'rasapi32.dll',
    'powrprof.dll',
    'shlwapi.dll',
    'urlmon.dll',
    'crypt32.dll',
    'version.dll',
    'msvcp140.dll',
    'ucrtbase.dll',
    'vcruntime140.dll',
    'd3d9.dll',
    'activeds.dll',
    'rstrtmgr.dll',
    'wtsapi32.dll',
    'd3d11.dll',
    'opengl32.dll',
]

with open("exports.yaml","w") as f:
	for dll in dlls:
		dllPath = system32_path+dll
		pe = pefile.PE(dllPath)
		dllExports = pe.DIRECTORY_ENTRY_EXPORT.symbols
		fnnames = []
		for symbol in dllExports:
			try:
				fnname = symbol.name.decode("utf-8")
				fnnames.append(fnname)
			except Exception:
				continue
		yaml.safe_dump({dll:fnnames},f)
```

Once the exports.yaml file has been generated, we can proceed to write a script that reads function names from it, calculates function hashes, and resolves all the functions accordingly.

```py
import pefile
import yaml
import idc
import ida_name
import sys

xorval_1 = 0x22065FED

ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

def compute_dll_hash(dllname,num):
	dllname = [ord(i) for i in dllname]
	dllname.append(0)
	for c in dllname:
		if c>=65 and c<=90:
			c += 32
		num  = c + ror(num,13,32)
	return num


def compute_fn_hash(fnname,num):
	fnname = [ord(i) for i in fnname]
	fnname.append(0)
	for c in fnname:
		num = c + ror(num,13,32)
	return num

# Location of all arrays containing the hashes 
hashTables = [0x405AFC,0x405BBC,0x405C80,0x405CDC,0x405D14,0x405D50,0x405D64,0x405D84,0x405DB0,0x405DC0,0x405DCC,0x405DE4,0x405E14,0x405E2C]

# Location where the resolved addresses of functions will be stored
outputTables = [0x4112AC,0x411368,0x411428,0x411480,0x4114B4,0x4114EC,0x4114FC,0x411518,0x411540,0x41154C,0x411554,0x411568,0x411594,0x4115A8]

# In each array of hashes, the first entry stores the hash of the DLL, XORed with the value 0x22065FED. The function hashes begin from the second element.
# The last element of each array of hashes is 0x0CCCCCCCC

end = 0x0CCCCCCCC

with open("exports.yaml","rb") as f:
	data = yaml.safe_load(f.read())
	dllNames = list(data.keys())
	storedDllHashes = [idc.get_wide_dword(arr) for arr in hashTables]
	for dllName in dllNames:
		print(f"Trying {dllName}")
		hash = compute_dll_hash(dllName,0)^xorval_1
		if hash in storedDllHashes:
			index = storedDllHashes.index(hash)
			itr = hashTables[index]+4
			itr2 = outputTables[index]+4
			dllfns = data[dllName]
			actualDllhash = hash^xorval_1
			dllfnHashes = [compute_fn_hash(fnname,actualDllhash) for fnname in dllfns]
			ida_name.set_name(outputTables[index],dllName)
			ida_name.set_name(hashTables[index],f"{dllName}_hashes")
			while(idc.get_wide_dword(itr)!=end):
				currentHash = idc.get_wide_dword(itr)^xorval_1
				if currentHash in dllfnHashes:
					ind = dllfnHashes.index(currentHash)
					ida_name.set_name(itr2,f"fn_{dllfns[ind]}")
				itr+=4
				itr2+=4

print("All functions resolved")
```
Running this script in IDA gives us the following results:

![](/images/rev/bm/bm05.png)


![](/images/rev/bm/bm06.png)


Likewise, we can write a script that, given a hash, simply prints the corresponding API name.
```py
import yaml

ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

def compute_dll_hash(dllname,num):
	dllname = [ord(i) for i in dllname]
	dllname.append(0)
	for c in dllname:
		if c>=65 and c<=90:
			c += 32
		num  = c + ror(num,13,32)
	return num


def compute_fn_hash(fnname,num):
	fnname = [ord(i) for i in fnname]
	fnname.append(0)
	for c in fnname:
		num = c + ror(num,13,32)
	return num

def get_function_name_from_hash(hash,xorVal=0):
	with open('exports.yaml','rb') as f:
		data = yaml.safe_load(f.read())
		dllNames = list(data.keys())
		for dllName in dllNames:
			fns = data[dllName]
			dllHash = compute_dll_hash(dllName,0)
			fnhashes = [compute_fn_hash(fn,dllHash) for fn in fns]
			if hash^xorVal in fnhashes:
				return fns[fnhashes.index(hash^xorVal)]
		return ""

print(get_function_name_from_hash(0x260B0745))
print(get_function_name_from_hash(0x6E6047DB))
print(get_function_name_from_hash(0xDA1AAEA2))
print(get_function_name_from_hash(0x576AC9D5))
print(get_function_name_from_hash(0x78403A7C))
print(get_function_name_from_hash(0x28805EB2))
```
Running this script gives us the following output:
```
HeapCreate
HeapAlloc
FindFirstFileW
FindNextFileW
FindClose
LoadLibraryW
```
Now, since we've resolved most of the functions from their hashes, we can start with the actual reverse engineering.

## Initial Checks
Once the API functions have been resolved, the malware proceeds to perform a series of checks:
```cpp
if ( !sub_40930C() && (unsigned int)sub_40155E() > 0x3C && sub_40931A(0) )
{
    // ....
}
```
- The first condition checks whether the current user running the process is a member of the Administrators group or not.
```cpp
int sub_40930C()
{
  return fn_SHTestTokenMembership(0, DOMAIN_ALIAS_RID_ADMINS);
}
```
- The second condition checks if the current operating system is Windows 7 (or Windows Server 2008 R2) and above.
```c
int sub_40155E()
{
  struct _PEB *peb; // eax
  unsigned int OSMajorVersion; // esi
  unsigned int OSMinorVersion; // edi

  peb = NtCurrentPeb();
  OSMajorVersion = peb->OSMajorVersion;
  OSMinorVersion = peb->OSMinorVersion;
  if ( OSMajorVersion == 5 && !OSMinorVersion || OSMajorVersion < 5 )
    return 0;
  if ( OSMajorVersion == 5 && OSMinorVersion == 1 )
    return 51;
  if ( OSMajorVersion == 5 && OSMinorVersion == 2 )
    return 52;
  if ( OSMajorVersion == 6 && !OSMinorVersion )
    return 60;
  if ( OSMajorVersion == 6 && OSMinorVersion == 1 )
    return 61;
  if ( OSMajorVersion == 6 && OSMinorVersion == 2 )
    return 62;
  if ( OSMajorVersion == 6 && OSMinorVersion == 3 )
    return 63;
  if ( OSMajorVersion == 10 && !OSMinorVersion )
    return 100;
  if ( OSMajorVersion == 10 && OSMinorVersion || OSMajorVersion > 0xA )
    return 0x7FFFFFFF;
  return -1;
}
```
- The third condition checks whether the current process token belongs to the builtin administrators group or not.

If these conditions are met, the malware continues its execution otherwise it attempts a UAC bypass.

## UAC Bypass

<img src='https://raw.githubusercontent.com/0xSh4dy/0xSh4dy.github.io/master/assets/img/rev/bm/bm06.png'>

The malware conducts a string decryption process by XORing specific values with 0x22065FED, resulting in the decrypted string `dllhost.exe`. It is also known as the COM Surrogate process. Further, it calls `LdrEnumerateLoadedModules` and passes the string `Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}` to the function `CoGetObject` which is used for UAC bypass.

## Normal Execution without UAC Bypass
The malware employs a string decryption routine and subsequently transfers the decrypted values to APIs associated with the Windows registry. Let's develop a code snippet that automates the string decryption task.
```py
import binascii
def decrypt_string(buffer,xorKey):
    answer = ""
    buffer = [i^xorKey for i in buffer]
    for item in buffer:
        try:
            val = binascii.unhexlify(hex(item)[2:]).decode("utf-8")[::-1]
            answer += val
        except Exception as e:
            pass
    return answer

buffer1 = [575233982, 575823787, 575102906, 574840767, 575365041, 577068932, 577331103, 577331102, 577920907, 574971825, 578772895, 577920925, 576806786, 577200031, 577658781, 570843028]
buffer2 = [577200032,577658766,577265540,574709640,577724312,570843017]

print(decrypt_string(buffer1,0x22065FED))
print(decrypt_string(buffer2,0x22065FED))
```
This gives us the following strings:
```
SOFTWARE\Microsoft\Cryptography
MachineGuid
```
![](/images/rev/bm/bm08.png)


It reads the value `MachineGuid` from the registry key `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography`, hashes it thrice, reverses the order of bytes and then encodes the hash using base64 encoding. In the resulting base64 string, it replaces `+` with `x`, `/` with `i` and `=` with `z`. It performs a string decryption to get the string `%s.README.txt`, replaces the format specifier with the base64 string generated earlier by calling the function `swprintf` and computes the hash of the resulting string `<base64Data>.README.txt`. It seems to be the ransom note where the malware will write a message for the victim. It checks whether the current user is `LocalSystem`. If the user is `LocalSystem`, it uses the current token otherwise it performs a series of steps:

- It calls the API function `NtQuerySystemInformation` to retrieve system information.
- It iterates through all processes in the system, verifying if the hash of some process name matches the value `0x3EB272E6`. If such process is found, it returns its process id.
- To maximize device coverage, this hash could represent a commonly found Windows process hash. Let's write a script to find out a process name whose hash matches this value.

```py
process_names = ["svchost.exe", "explorer.exe", "taskmgr.exe", "spoolsv.exe", "winlogon.exe", "services.exe", "lsass.exe", "wmiprvse.exe", "chrome.exe", "firefox.exe", "iexplore.exe", "wininit.exe", "dllhost.exe", "csrss.exe", "notepad.exe", "cmd.exe", "dwm.exe", "system.exe", "winword.exe", "outlook.exe"]

ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

def compute_hash(name,num):
	name = [ord(i) for i in name]
	name.append(0)
	for c in name:
		if c>=65 and c<=90:
			c += 32
		num  = c + ror(num,13,32)
	return num

for name in process_names:
	if compute_hash(name,0)==0x3EB272E6:
		print(name)
		break
```
Running this script, we get the process name which is `explorer.exe`.

![](/images/rev/bm/bm09.png)


The malware calls `NtOpenProcess` to get a handle to the process `explorer.exe` and passes the prcoess handle to the function `NtOpenProcessToken` to retrieve the token. Further, it calls `NtDuplicateToken` to create a duplicate of the existing token. If the malware fails to retrieve the duplicated token, it performs a series of steps to get a token.

- It calls the API function `NtQuerySystemInformation` to retrieve system information.
- It iterates through all processes in the system, verifying if the hash of some process name matches the value `0xB7E02438`. If such process is found, it returns its process id.

By running the script we wrote earlier to calculate the hashes of common process names, we obtain the process name as `svchost.exe`. The process id of `svchost.exe` is calculated and passed to the function `NtOpenProcess` with the `PROCESS_ALL_ACCESS` flag which gives a handle to the process. Further, it checks if the process `svchost.exe` is running as a 64-bit process. If yes, it calls a function at the offset 0x64cc from the image base.

![](/images/rev/bm/bm10.png)


The malware allocates memory of size 513 bytes using `RtlAllocateHeap`, and copies a global buffer into it. 

![](/images/rev/bm/bm11.png)


## Shellcode Extraction

![](/images/rev/bm/bm12.png)


Using PE bear, we notice that the offset `0x12000` corresponds to the virtual address of the `.rsrc` section. 

![](/images/rev/bm/bm13.png)


The first dword stored in the `.rsrc` section is a seed and the second dword denotes the size of the encrypted data stored there. 
```c
int __stdcall keygen(unsigned int a1, int *seed)
{
  int v2; // edx

  v2 = 0x8088405 * *seed + 1;
  *seed = v2;
  return (v2 * a1) >> 32;
}
```
The seed is modified with each call to this function, thereby returning a different value everytime. After that, it xors each byte of the encrypted data with the corresponding byte of the generated key. After that, it decompresses the decrypted data by using the atlib decompression algorithm. Let's write a script to decrypt this encrypted buffer. The initial value of the seed comes from the first dword present in the `.rsrc` section i.e. `0xffcaa1ea`.

```py
import struct

def key_generator(value,seed):
    v2 = (0x8088405 * seed + 1)&0xffffffff
    return ((v2 * value) >> 32)&0xffffffff, v2

def generate_keystream(bufLen):
    seed = 0xffcaa1ea
    newSeed = seed
    keystream = b''
    for i in range(bufLen):
        value,newSeed = key_generator(seed,newSeed)
        keystream += struct.pack("<I",value)
    return keystream

def decrypt_buffer(keystream,buffer):
    bufLen = len(buffer)
    decrypted = []
    for i in range(bufLen):
        x =  buffer[i]^keystream[i]
        decrypted.append(x)
    return bytes(decrypted)

        
encBuf1 = b'"\xefx\x91\xf2=_U%\xa4~\xff\x89t\xf3j\x83q\xcew\x01\x08v)w\xe38u\xd0U\x81gdv\xb9Y\x9f\x14L\xa5\xabb\xfd\x8aa\x15\x96b\xc5v\x880\x993\x83 "\xafI63\x07\xa3\xcc\xa6Z\x1aC\xee\xcf\xf0&\xfch\xbb\x02\xccW\xa1\xaa\x99\xfa\x02*q\xf3\xe8\xf2j\xbd\xab\x9f"\n\xa81\xc1q\ns1g\xce8j\xde\x0cm55\x9b\x1eS(0\xf6\xc7\xef\xeajIXV\x97\xd9\xfc]1s\xfd3\x96\xebT?:\x1f\x12$\x16o6n_\x1d\xaa\\I\x8d5}\xb1x\x00Gc\xcf\xa3\xba\xff]\x11\xf2pO)Sso}\xaf\xf4\x13\x0bp\xccX\t\xefn\xfak\xf6/\x0e\x87\x9b\xae\xf2\xba\xbd\x1bT${NN5\xc6v>b\xfb\x92\xf2T\x87\xbd\x87\x07\xd6\xfe\xe7\xc5\xb5\x94\xf2\x1f\x16\x7f6%\xf8\xc6Z>\x8a\'\x01\x8f\xc2\xb1\x9a\xd3\x0f\x06\xc5\x9e\x0b$\x99\x196=I\xb1g}\xb0\x8eS\xedk\x16[\xb6EU\x1a@\xc8n<p\xc1\x07i\x9a"E\xd4\xb8\xaf\x12\x1e[\xaa\xf2\x02\xad\x17\xa4+L\xc7=\xf0>\xbc\n\x07N\xa4m7\xb9\x0fF\xdfWt\x0f\\\xff:q\xdb\xaa\xe6TPQ\xc2\xfd\xe0\x9aN\xa3%\xdb\xb1k\xba\xcd\xd3\x07 \xe4:)\x1c\x8bo\xed9\xf8\x1eS\x19\xdd\xcc\x9b;\x864Z\xf3\x16\xe7n\xb2\xbd\xf0\xcd\x8e\xb6\x93$\x82:\x08\xc0\x96\x04Y\xb8\xf0\xaaQ\x1dg!\x03\x95\xa2\x0e\x0c\xc9VP%\xb0^\xce\xadN\xe9y\xeav7\x15\xfa\x96\x84\x08\x17\xf7q\\-\x18\x05\xa3\xec\x12.\xa7\xf9+\xcb\x05I\xaf\x1eG\xad\xee\xac\xd1\x05\x15\x9b\xe3\x95\xbf8\x05\xdf\xf1$o\xc9\xa3\xecf~\xedS\xe9\x01\x15\xb0\xe2\x1dh\x15\x99k\xeb\xc3!\x99\x93\xd8)\xd1\x1d\xa9AU\xa4g\xeez7\xae\xa8\x08\xc9,\x08\xb8\xbft&lj\x04\xd5\xfd0\xe6\xf9N\x87\xa3\xf3L9P \xf86\x8d\x1a\xbd\xd2\xb5H\x00\x81\xf2?\x80\x0e\x14\xd6\x12\x03WCU\xcf\x02\x00'
encBuf2 = b'\x00_|\xd9\x1a\x14_\xd6!\x81{4\xc1!\xa0<\xd40\x9c?\x80\xe4\xc6)w\xe3p\xf8|q\x01gdv\xf1\x9e\\\x9c\xc7)5ZS\x7f\xac\xc4\r\xf1\xe1\xb1\x14v\xd4\x92\xac\xbe\xd5\x13/Z\xdb\xf8/\x87\xba\xed\r\xbf\xdc\x9eJ=\x14\xfd6W<\x94#\x9f\xfc\xe5\x83\x98I\x02\xe2\xc9\xd2\'\x83\x1c\xe5N\x8c]L\n\x1e;\xf2\xf3\x86T\x85_\xf3\x92\xca5\x07,\x1f\xe5\x89\x90k\xb4\xcbjI\x10\xdd\x14V3,\xe9?v\xf5\xda(\\3\xd9k4\x04\x16o\xc9\xbe\x19\xd7\xee\xcau3\xc0\x95\xecyL\xcc\xd3\ne\t\xb7\x97\xbb\xd5p\x03\xa0\xa0\xcd\x8f\xaa\xa2L\x90S\xb3\x84\xd0\xc8x\x02So\x15c\xa3\xfb\xbf\xbe\xba\xef\xa6\x8aX\x8b\xa7}\x8e\xbe\x9b\x16\xb1\xad\xaa\x8a\x94\xf9\xe1>7\x81\xe0\xd0\xc1FM\xce\x85S\xb7\xb8\xdaMx\x01;\xbe-\x81\x84`\x9f\xb2BV\xcf\x8c\xcao\x93\xa8>\x83;b\x13\xec\xa4}\xb2\x8f\x8f\xd60\x07Lf\xf2\xd0\xf0i:U\xbe\xab\xed\x8c4\xb2&C\xe4\x98K\x19\x94\xc2\x19\xcf*\xab\x1d\x99(\x94B\xb5B\x8a\xd0\xa1\xc4\x06/\x88\x962\xeb\x9f\xab$J\xef\xd2\xaah"\xc5v\xea\xfc\xee\xd03\xe7N\xda\'\xc6\xff\xff\x81#5\x05~\xf7h#\x7f\xa4T\x00k\xc8\x15u[\xbb\x19\xddG\xca\xb4\xcal\xca\xbf\x9dX\xaeps\xa8v@\xf5\xe7\xe1\xe4\xc9\r\x11A\xd2\x02\xe5\x18\xef\xd4\xd4\x13\x89\x0e<\xdeuDB\x19\xdb\x12F\xbb5\x91\xf9\x9f\xbc\x8b\x8e\xf2B\x15\xc7G\x1c\\$\xf9\xa3\x88\xa2\x80\xdc\xf0\xb1\x17\x0c\xcd\x80\xd4\x8cg/\x15N\xdc\x1fg\x1a\xfe\x8c\xa4l;\xb7\xa5\xd5\xb7p\xba\x10\xd9\xf9h\xed\x06\xf9\x84\xdb\xf6\xa1\x89\xa8\xd7\xa8,\x0e\xc6\xb6k\xd1\x12\xd8\x92-|P\xd8\xfe|\xfc\xac|+\x9e\xab\xd7g\x87\x18\x83\x90_t.d\xb2\xa8!8\xbaj[\xa4F!\xc5\x97\xeeP\x8fr9:\xd9\xf5\xdf\xc6\xe5\xd3\xbf\xaf\xbdP\x03h\x81\x04\r_M\xc0\xb8\xeb\xbe\xc73dhD<t\xee_\xee\xdd\xeaG\x01R\xc5l!\xee\x96U\xcdi\xfe\x14-\x99\x14b\xaa\x82n\xdb\xdcr\xdbH\xce\xe4\x1cQ\xe0\xedh\xa8^.c\x17O\x1b\xde\xb3\x16\x1f\x9ex\xfb \xa4Qd\x17\xa0\xef\xdcy\xe7\x92;\xe1Q\xdci\xc9\xaeVU\xd3\xaf2\xc9;\x98\x0f#\x7f\xd13\xa8\x14o\x1f\x0e.,\xcd\xccA\xa2\x153\xdd\xc571\xeen\xf3\xbaD=w3\xa1)\x9f\tXYs\xe2O\x98\xa2E\xeb\x072\xb0^\xda\xf9\xda\xe4\x9e]2\xaat\xde\xd4(\x94\xc8\xd4B"Z\xb87e\xb9r^\xaa\xbe-\xde\xa6\x02\xf3\xc7[\xfc\xb6h\nVA\xcf\xd1\xf39\x9f\tm\x8f\xa64\xd0\xaa_\x8c\x02\x811\xac\x8a-\xe2!F\xb37\xe1b\xe0 (4\xff\x02\xf2'
keystream = generate_keystream(len(encBuf1))
decBuf1 = decrypt_buffer(keystream,encBuf1)
decBuf2 = decrypt_buffer(keystream,encBuf2)
with open("shellcode1.bin","wb") as f:
    f.write(decBuf1)

with open("shellcode2.bin","wb") as f:
    f.write(decBuf2)

```
Running this script gives us two files `shellcode1.bin` and `shellcode2.bin` which can be further analysed.

## Config Extraction

![](/images/rev/bm/bm14.png)


Let's write a python script to generate the keystream, decrypt and decompress the data stored in the `.rsrc` section.
```py
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

dwordsBuf = get_dwords_from_byte_buffer(read_rsrc_section())
encData = read_rsrc_section()[8:]
seed = dwordsBuf[0]
bufLen = dwordsBuf[1]
key = generate_key(seed,bufLen)
decryptedBlob = decrypt_buffer(encData,key,bufLen)
decompressedData = decompress(decryptedBlob)
print(decompressedData)
```

![](/images/rev/bm/bm15.png)


We can see that the decompressed data contains various base64 blobs separated by null bytes. Continuing our analysis, we quickly figure out that the malware reads and decodes these base64 encoded chunks. Let's enhance the existing script by incorporating a function that enables the decoding of the decompressed data.
![](/images/rev/bm/bm16.png)


```py
# Completing the existing script
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

base64Blobs = decompressedData[204:]
configData = decode_config(base64Blobs)
print(configData)
```
![](/images/rev/bm/bm17.png)




### Summary
- Extracted configuration data
```
encsvc
thebat
mydesktopqos
xfssvccon
firefox
infopath
winword
steam
synctime
notepad
ocomm
onenote
mspub
thunderbird
agntsvc
sql
excel
powerpnt
outlook
wordpad
dbeng50
isqlplussvc
sqbcoreservice
oracle
ocautoupds
dbsnmp
msaccess
tbirdconfig
ocssd
mydesktopservice
visio
mepocs
memtas
veeam
svc$
backup
sql
vss
https://paymenthacks.com
http://paymenthacks.com
https://mojobiden.com
http://mojobiden.com
```