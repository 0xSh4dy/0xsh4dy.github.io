---
title: Reversing WarZone Rat
date: 2022-12-22
tags: [malware,rat,windows,cpp]
---

## Description
WarZone is a Remote Access Trojan (RAT) that is sold on a publicly available website, as a Malware-as-a-Service.

`MD5`: 48FF98ED6AE74DA9C1FEF59B40699BAE
<br><br>
`SHA256`: 4537FAB9DE768A668AB4E72AE2CCE3169B7AF2DD36A1723DDAB09C04D31D61A5
<br><br>

## Reversing and Config Extraction
Starting our analysis from the function `start`, we quickly spot a function `sub_405D70()` which sets the value of a global variable `dword_54DB64` to 32 and then calls `HeapAlloc`. After calling `sub_405D70`, the program calls a function `sub_405D9D(&dword_419000, (unsigned int)&unk_41902C);` where dword_419000 is a pointer to functions.
```c
.data:00419000 dword_419000    dd 0                    ; DATA XREF: start+66↑o
.data:00419004                 dd offset sub_4011CD
.data:00419008                 dd offset sub_4011EF
.data:0041900C                 dd offset sub_4011FE
.data:00419010                 dd offset sub_40120D
.data:00419014                 dd offset sub_40121C
.data:00419018                 dd offset sub_40122B
.data:0041901C                 dd offset sub_40123A
.data:00419020                 dd offset sub_40125C
.data:00419024                 dd offset sub_40126B
.data:00419028                 dd offset sub_401280
```
`sub_405D9D` loops through all of these functions and eventually calls them, and these functions are doing some basic initialization stuff. After that, we notice a function call `sub_413435(v6, v6)`. 

We see that this function calls a bunch of other functions. Decompiling some of these functions, we observe that the argument passed to them might be a struct.

![](/images/warZone/img1.png)

This function is probably an initializer that initializes the member of some struct. To fix this thing, we reset the pointer type of `this` and then create a new struct type. I'm setting the default type of each struct member as `_DWORD` for making reversing easy. I'll fix the types later if necessary. This would make our life as a reverse engineer easier than before. Similarly, we can define new struct types for other functions as well, wherever necessary.  

After that, the program calls `GetModuleFileNameA(0, Filename, 0x104u)`.Here, the first argument is NULL, so the API call would retrieve the path of the executable for the current process. After that, data is read from the executable file (the current executable) and a pointer to the data is passed to the function `sub_411BF8(v10, (int)current_exe_data_ptr, 8538, &v11)`. 

![](/images/warZone/img3.png)

This seems to be a hash function. Googling some of these constants, we find out that this is `Murmur` hash. This hash is just used to ensure that only instance of the malware runs at a time. If the hash already exists, the call to `CreateEventA` returns a handle to the existing object and `GetLastError()` returns `ERROR_ALREADY_EXISTS`. In this case, the malware performs cleanup by freeing the allocated memory, handles, etc. and then terminates. But, if the call to `CreateEventA` returns a new handle, the malware starts its actual work.

```cpp
if ( hObject )
      {
        RegCreateKeyExA(
          HKEY_CURRENT_USER,
          "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
          0,
          0,
          0,
          0xF003Fu,
          0,
          &phkResult,
          &dwDisposition);
        RegSetValueExA(phkResult, "MaxConnectionsPer1_0Server", 0, 4u, Data, 4u);
        RegSetValueExA(phkResult, "MaxConnectionsPerServer", 0, 4u, Data, 4u);
        RegCloseKey(phkResult);
        sub_405A10((int)&struct_this_20_var, 0);
        sub_4114A6((PHKEY)&struct_this_13_var, &struct_this_20_var);
        sub_404EE7((int)v21, 0, (int)&struct_this_20_var, (int)&struct_this_13_var);
        sub_401052(0, (char *)pszPath, 0, 0x208u);
        SHGetFolderPathW(0, 28, 0, 0, pszPath);
        lstrcatW(pszPath, L"\\Microsoft Vision\\");
        CreateDirectoryW(pszPath, 0);
        if ( struct_this_20_var.dword15 && !sub_40FBFC() )
        {
          if ( sub_40F51D() == 10 )
            sub_411AB9(0);
          else
            sub_411A3C(0);
        }
        if ( struct_this_20_var.dword16 && sub_40FBFC() )
          sub_412FD7();
        if ( struct_this_13_var.dword9
          || (sub_411136(
                (PHKEY)&struct_this_13_var,
                (LPCWSTR)struct_this_20_var.dword6,
                struct_this_20_var.dword8,
                (LPVOID)struct_this_20_var.dword17),
              !struct_this_20_var.dword6) )
        {
          if ( struct_this_20_var.dword14 )
            sub_411F13();
          sub_404E5B((DWORD *)v21);
        }
        else
        {
          v15 = 0;
          sub_40362D((WCHAR **)&lpAddress, (LPCWSTR *)&struct_this_13_var.dword8);
          sub_410BD9(&v16, (LPCWSTR *)&lpAddress, &v15, v7);
          sub_405EA5(lpAddress);
          sub_405EA5(0);
        }
        sub_404BC0(v21);
      }
```

The program creates a new registry key `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet\Settings`, sets the values `MaxConnectionsPer1_0Server` and `MaxConnectionsPerServer` to 10 and then closes the handle to registry key. Now, let's reverse the function `sub_405A10`. It eventually calls `sub_411CA2` which is really interesting.

![](/images/warZone/img4.png)
It stores the address of `sub_411CA2` into v0 and loops back until it reaches at the beginning of the PE file ('\x90ZM') is the famous MZ header present at the beginning of PE files. A pointer to the beginning is then passed as the second argument to the function `sub_410346`. 

![](/images/warZone/img5.png)
Consider this condition: `if ( *(_WORD *)a2 != 0x5A4D )` . 0x5A4D is the magic number for PE executables which is present as `e_magic` in the struct `IMAGE_DOS_HEADER`. Let's change the type of `a2` to `PIMAGE_DOS_HEADER`. 

![](/images/warZone/img6.png)
Now, it looks better!
`e_lfanew` is the last member of the DOS header structure, it holds an offset to the start of NT headers. This member is important to the PE loader on windows systems because it tells the loader where to look for the file header. From line 29, `v4 = (char *)pe_base + pe_base->e_lfanew;` gives the address of the start of NT headers. Now, consider this condition `  if ( *(_DWORD *)v4 != 0x4550 )`. 0x4550 is the signature present in NT headers (defined by the struct IMAGE_NT_HEADERS). All we need to do to make it look better is to set the type of v4 to `PIMAGE_NT_HEADERS`. After that, the malware checks whether the exe is suitable for i386 or AMD64 i.e 32 bit or 64 bit (using the value of Machine field in IMAGE_NT_HEADERS). Changing the types of some other local variables, by checking the values dynamically, we get the following code:

```cpp
if ( Machine == 0x14C )
  {
    var_this_temp->dword17 = 1;
    var_this_temp->sptr_nt_hdr = var_nt_headers;
    sub_9E2F91(
      (IMAGE_OPTIONAL_HEADER *)&var_this_temp->sptr_tdos_hdr,
      arg_exe_start,
      var_nt_headers->OptionalHeader.SizeOfHeaders);
    nt_headers = var_this_temp->sptr_nt_hdr;
    v15 = 0;
    var_sec_header = (IMAGE_SECTION_HEADER *)((char *)&nt_headers->OptionalHeader
                                            + nt_headers->FileHeader.SizeOfOptionalHeader);
    if ( nt_headers->FileHeader.NumberOfSections )
    {
      do
      {
        sub_9F0AC3((struct_this_4 *)&var_section_header, arg_exe_start, var_sec_header, (int)&var_section_header);
        sub_9E2296(
          (struct_this_5 *)&var_this_temp->dword12,
          var_section_header.Name[0],
          *(int *)&var_section_header.Name[4],
          var_section_header.Misc.PhysicalAddress,
          var_section_header.VirtualAddress,
          var_section_header.SizeOfRawData,
          var_section_header.PointerToRawData,
          var_section_header.PointerToRelocations,
          var_section_header.PointerToLinenumbers,
          *(int *)&var_section_header.NumberOfRelocations,
          var_section_header.Characteristics,
          v13,
          v14);
        ++var_sec_header;
        ++v15;
      }
      while ( v15 < var_this_temp->sptr_nt_hdr->FileHeader.NumberOfSections );
    }
  }
  else if ( Machine == 0x8664 )
  {
    v8 = 0;
    var_this_temp->dword11 = var_nt_headers;
    var_this_temp->dword17 = 0;
    sub_9E2F91(
      (IMAGE_OPTIONAL_HEADER *)&var_this_temp->sptr_tdos_hdr,
      arg_exe_start,
      var_nt_headers->OptionalHeader.SizeOfHeaders);
    dword11 = var_this_temp->dword11;
    e_res2 = (IMAGE_SECTION_HEADER *)(dword11 + *(unsigned __int16 *)(dword11 + 20) + 24);
    v16 = (IMAGE_DOS_HEADER *)e_res2;
    if ( *(_WORD *)(dword11 + 6) )
    {
      do
      {
        sub_9F0AC3((struct_this_4 *)&var_section_header, arg_exe_start, e_res2, (int)&var_section_header);
        sub_9E2296(
          (struct_this_5 *)&var_this_temp->dword12,
          var_section_header.Name[0],
          *(int *)&var_section_header.Name[4],
          var_section_header.Misc.PhysicalAddress,
          var_section_header.VirtualAddress,
          var_section_header.SizeOfRawData,
          var_section_header.PointerToRawData,
          var_section_header.PointerToRelocations,
          var_section_header.PointerToLinenumbers,
          *(int *)&var_section_header.NumberOfRelocations,
          var_section_header.Characteristics,
          v13,
          v14);
        ++v8;
        e_res2 = (IMAGE_SECTION_HEADER *)v16->e_res2;
        v16 = (IMAGE_DOS_HEADER *)((char *)v16 + 40);
      }
      while ( v8 < *(unsigned __int16 *)(var_this_temp->dword11 + 6) );
    }
  }
```

![](/images/warZone/img7.png)
This initializes various structs which are probably going to be used later. Let's move back to the caller of this function and reverse further.
Using dynamic analysis, we can find that the call to the function `sub_8233BF((char **)&lpAddress, a2, ".bss");` returns a pointer to the string `.bss`.

![](/images/warZone/img8.png)

The call `sub_9F02B9(&var_mtd_struct, &var_section_data, (LPCSTR *)var_bss_str);` stores the section header for .bss at `var_section_data`.

![](/images/warZone/img9.png)

These values match with the values calculated by PE Bear. 

![](/images/warZone/img10.png)


Moving forward, we find a function `sub_9360AA` with a similar pattern to RC4, so I decided to find out the decrypted data using dynamic analysis. The decrypted data is present at `0xab270`, we can use IDAPython to retrive the data present at this address.

![](/images/warZone/img11.png)

![](/images/warZone/img12.png)

![](/images/warZone/img13.png)

```py
Python>data = get_bytes(0xab270,70)
Python>for c in data:
Python>     print(hex(c),end=',')

0x16,0x0,0x0,0x0,0x31,0x0,0x36,0x0,0x35,0x0,0x2e,0x0,0x32,0x0,0x32,0x0,0x2e,0x0,0x35,0x0,0x2e,0x0,0x36,0x0,0x36,0x0,0x57,0x4,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x88,0x13,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x14,0x0,0x0,0x0,0x52,0x0,0x53,0x0,0x31,0x0,0x54,0x0,0x57,0x0,0x39,0x0,0x56
```
![](/images/warZone/img14.png)

Taking some elements from this list,
```py
d1 = [0x31,0x0,0x36,0x0,0x35,0x0,0x2e,0x0,0x32,0x0,0x32,0x0,0x2e,0x0,0x35,0x0,0x2e,0x0,0x36,0x0,0x36]
for c in d1:
    if c!=0x0:
       print(chr(c),end='')

```
This gives us the C2 `165.22.5.66`. Also, [0x57,0x4] is a common method of storing the port, i.e port 0x457 which is `1111`.





