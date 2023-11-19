---
title: REvil Ransomware
subtitle: 
tags: [unpacking, x64dbg,ransomware,malware,ida]
comments: true
date: 2022-07-28
---

REvil or Sodinokibi ransomware is a powerful ransomware that encrypts files. It uses advanced encryption techniques and can operate without connection to control servers.

So, let's get started

---

`Malware sample` : [https://app.any.run/tasks/2336fa81-a8c9-41b5-8a7a-e958047097f2/#](https://app.any.run/tasks/2336fa81-a8c9-41b5-8a7a-e958047097f2/#)
`File Info`: PE32 executable (GUI) Intel 80386 (stripped to external PDB), for MS Windows, UPX compressed
`MD5` : 61c19e7ce627da9b5004371f867a47d3
`SHA1` : 4f3b4329871ec269043068a98e9cc929f603268d
`SHA256` : bf7114f025fff7dbc6b7aff8e4edb0dd8a7b53c3766429a3c5f10142609968f9
`SSDEEP` : 6144:YONNYdX7HkqEHcTY6uoZzFyKAuGnlOOkl8tuGogbOIVmda9J4:YONNoX7HMHcTY6uoZzFyfONlwNB2


## Unpacking
Hmm, this executable has been packed using the UPX packer. We can either use the UPX packer to unpack it or unpack it dynamically (which is an interesting method). To do that, we'll set breakpoints on some functions such as `CreateProcessInternalW` (whenever a new process is created), `VirtualProtect`(whenever permissions of a memory region are changed), `ResumeThread`(whenever a thread resumes). Also, we need to calculate the return value of `VirtualAlloc`(to find the address of the newly allocated memory segment). Set a breakpoint at some instruction when `VirtualAlloc` is about to return, let's say ret, note down the value of rax, follow that address in dump and then continue.
![](/images/revil/img_1.png)
<br>
![](/images/revil/img_2.png)

Boom, a PE file! We can dump it and then start reversing it using IDA.

First of all, we need to note down the entry point using IDA. It is present at the offset 0x36E6. Now, let's follow `call sub_40369d`. We immediately notice the instruction `call dword_41cb64` (a call to dword instead of some address). This points to the fact that the address of API call has not been resolved yet which means that some dynamic import would be resolved here. Now, there's only one function before this call instruction(0x406A4D), so it might be the function where dynamic imports are being handled. Here, in IDA, the executable base address is 0x400000 and the function we're looking for is present at the offset 0x6A4D. One more thing, we cannot see any import table in IDA.

![](/images/revil/img_3.png)

Now, let us construct the import table using `Scylla`. To do this, load the executable in x32dbg, follow the function with the offset 0x369d until you reach the one with the offset 0x6A4D. Step over this instruction and yeah, now we can see that the imports have been resolved. Using Scylla (a plugin present in x64/x32dbg), take a dump, click on `IAT Autosearch`, after that click on `GetImports` to view the imported DLLs. Everything is set, now we can fix the dump by clicking on the `Fix Dump` option. This would fix the dump we took earlier and save the new file. 

![](/images/revil/img_4.png)

Let's us look the fixed dump in PEBear to verify whether the imports have been fixed or not.
![](/images/revil/img_6.png)

Now, we can change the value of the Entry Point to 36E6 using PE bear. Interesting, everything is set! Now we can use IDA to reverse this dump.
![](/images/revil/img_5.png)
<br>
![](/images/revil/img_7.png)

Interesting!!!!

## String Decryption
Now, let us surf through some functions to find out something interesting.

Here, we can see that the program calls `CreateMutexW(0, 0, Name);` This buffer `Name` is a local buffer which is passed by reference to the function `sub_EC4E03`.

```
  sub_EC4E03(&unk_EDCC28, 1982, 15, 86, Name);
```

`unk_EDCC28` is just some data, we need to find out the working of the function `sub_EC4E03`.

![](/images/revil/img_8.png)

```
int __cdecl sub_EC4E03(int a1, int a2, int a3, int a4, int a5)
{
  return sub_EC59FC(a2 + a1, a3, a2 + a1 + a3, a4, a5);
}
```

Okay, so `sub_EC4E03` calls another function which contains some interesting code snippets. Basically, this function is an implementation of RC4 algorithm. Let's rename some variables and arguments to make our life easier.

![](/images/revil/img_9.png)

```
_BYTE *__cdecl sub_EC4E03(char *arg_enc_data, int arg_off_1982, int arg_off_15, int arg_off_86, int arg_str_decrypted)
{
  return mlw_rc4(
           (int)&arg_enc_data[arg_off_1982],
           arg_off_15,
           (int)&arg_enc_data[arg_off_1982 + arg_off_15],
           arg_off_86,
           (_BYTE *)arg_str_decrypted);
}
```

Okay, so 15 is probably the length of the key for RC4 decryption, starting from `arg_enc_data[1982]`. The program is probably trying to decrypt the data present at `arg_enc_data[1982+15]`. We can extract the key and some encrypted data that is passed to the function.

Interesting! So, the key is `485A8EEEF3041AE753246740A753FF`. We can pick some amount of data from `arg_enc_data[1997]` and decrypt it using cyberchef.

![](/images/revil/img_10.png)

Yes, our assumption was correct. This is actually RC4 because the string `Global` is a valid string. Now, we need to find xrefs(cross references) to the function `sub_EC4E03` to decrypt various encrypted strings present in the malware. Performing it manually is boring and time consuming task. We can use IDAPython API to automate the process. In fact, we can create a script to automatically decrypt the encrypted strings using IDAPython API.

```py
import idaapi,idc,idautils
from Crypto.Cipher import ARC4

def rc4decrypt(data,key):
    try:
        cipher = ARC4.new(key)
        dec_text = cipher.decrypt(data)
        dec_text = dec_text.replace(b"\x00",b"")
        return dec_text
    except Exception:
        return ""

def get_xrefs(fn_addr):
    return [addr.frm for addr in idautils.XrefsTo(fn_addr)]


def get_reg_value(ptr_addr, reg_name):
    e_count = 0
    while e_count < 500:
        e_count += 1
        ptr_addr = idc.prev_head(ptr_addr)
        if idc.print_insn_mnem(ptr_addr) == 'mov':
            if idc.get_operand_type(ptr_addr, 0) == idc.o_reg:
                tmp_reg_name = idaapi.get_reg_name(idc.get_operand_value(ptr_addr, 0), 4)
                if reg_name.lower() == tmp_reg_name.lower():
                    if idc.get_operand_type(ptr_addr, 1) == idc.o_imm:
                        return idc.get_operand_value(ptr_addr, 1)
        elif idc.print_insn_mnem(ptr_addr) == 'pop':
            ## Match the following pattern
            ## push    3
            ## pop     edi
            if idc.get_operand_type(ptr_addr, 0) == idc.o_reg:
                tmp_reg_name = idaapi.get_reg_name(idc.get_operand_value(ptr_addr, 0), 4)
                if reg_name.lower() == tmp_reg_name.lower():
                    ## Get prev command
                    tmp_addr = idc.prev_head(ptr_addr)
                    if idc.print_insn_mnem(tmp_addr) == 'push':
                        if idc.get_operand_type(tmp_addr, 0) == idc.o_imm:
                            reg_value = idc.get_operand_value(tmp_addr, 0)
                            return reg_value
        elif idc.print_insn_mnem(ptr_addr) == 'ret':
            pass
    pass


def get_fncall_args(fn_addr, n_args):
    arg_count = 0
    ptr_addr = fn_addr
    call_args = []
    while arg_count<n_args:
        ptr_addr = idc.prev_head(ptr_addr)
        if idc.print_insn_mnem(ptr_addr) == "push":
            if idc.get_operand_type(ptr_addr,0) == idc.o_reg:
                reg_name = idaapi.get_reg_name(idc.get_operand_value(ptr_addr,0),4)
                reg_value = get_reg_value(ptr_addr,reg_name)
                call_args.append(reg_value)
                arg_count += 1
            elif idc.get_operand_type(ptr_addr,0) == idc.o_imm:
                call_args.append(idc.get_operand_value(ptr_addr,0))
                arg_count += 1
            else:
                pass
    return tuple(call_args)


def decrypt_string(fn_address):
    try:
        call_args = get_fncall_args(fn_address,4)
    except:
        print("Error, cannot get function arguments")
        return
    enc_data_start = call_args[0]
    key_offset = call_args[1]
    key_len = call_args[2]
    enc_str_len = call_args[3]
   
    key_start = enc_data_start + key_offset
    todec_data_start = key_start+key_len
    key_data = idc.get_bytes(key_start,key_len)
    todec_data = idc.get_bytes(todec_data_start,enc_str_len)
    decr = rc4decrypt(todec_data,key_data)
    print(decr)

mlw_string_decryptor = 0xec4e03
xrefs = get_xrefs(mlw_string_decryptor)
for xref in xrefs:
    decrypt_string(xref)
```
![](/images/revil/img_11.png)

Jeez! The decrypted strings are:
```
b'fld'
b'fls'
b'ext'
b'pk'
b'pid'
b'sub'
b'dbg'
b'wht'
b'wfld'
b'wipe'
b'prc'
b'dmn'
b'net'
b'nbody'
b'nname'
b'img'
b'fast'
b'none'
b'true'
b'false'
b'-nolan'
b'exp'

b'rnd_ext'

b'stat'
b'{"ver":%d,"pid":"%s","sub":"%s","pk":"%s","uid":"%s","sk":"%s","unm":"%s","net":"%s","grp":"%s","lng":"%s","bro":%s,"os":"%s","bit":%d,"dsk":"%s","ext":"%s"}'
b'{UID}'
b'{KEY}'
b'{EXT}'
b'{USERNAME}'
b'{NOTENAME}'
b'SYSTEM'
b'USER'
b'.lock'
b'{UID}'
b'{KEY}'
b'{EXT}'
b'{EXT}'

b'sub_key'
b'pk_key'
b'sk_key'
b'0_key'
b'program files'
b'program files (x86)'
b'sql'
b'https://'
b'wp-content'
b'static'
b'cont'
b'include'
b'uploads'
b'news'
b'data'
b'admin'
b'images'
b'pictures'
b'image'
b'temp'
b'tmp'
b'graphic'
b'assets'
b'pics'
b'game'
b'jpg'
b'png'
b'gif'
b'.bmp'
b'cmd.exe'
b'/c vssadmin.exe Delete Shadows /All /Quiet & bcdedit /set {default} recoveryenabled No & bcdedit /set {default} bootstatuspolicy ignoreallfailures'

b'Domain'
b'WORKGROUP'

b'LocaleName'
b'%08X%08X'
b'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'
b'productName'
b'explorer.exe'
b'Global\\206D87E0-0E60-DF25-DD8F-8E4E7D1E3BF0'
b'runas'
b'qJiQmi65SC9GfVbj'
b'CreateStreamOnHGlobal'
b'advapi32.dll'
b'crypt32.dll'
b'gdi32.dll'
b'mpr.dll'
b'ole32.dll'
b'shell32.dll'
b'shlwapi.dll'
b'user32.dll'
b'winhttp.dll'
b'winmm.dll'
b'\\\\?\\UNC'
b'\\\\?\\A:\\'

b'POST'
b'Content-Type: application/octet-stream\r\nConnection: close'
b'win32kfull.sys'
b'win32k.sys'
```


TO BE CONTINUED....
