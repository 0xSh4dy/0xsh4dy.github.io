---
title: Kernel root exploit via UAF and fork()
subtitle: 
tags: [kernel, heap, uaf,fork,cred,kmalloc,pwn]
comments: true
date: 2022-06-29
---

Hey everyone! This post throws some light on spawning a root shell by exploiting a simple UAF. First of all, let's have a look on the cred struct.

```c
struct cred {
    atomic_t    usage;
#ifdef CONFIG_DEBUG_CREDENTIALS
    atomic_t    subscribers;    /* number of processes subscribed */
    void        *put_addr;
    unsigned    magic;
#define CRED_MAGIC  0x43736564
#define CRED_MAGIC_DEAD 0x44656144
#endif
    kuid_t      uid;        /* real UID of the task */
    kgid_t      gid;        /* real GID of the task */
    kuid_t      suid;       /* saved UID of the task */
    kgid_t      sgid;       /* saved GID of the task */
    kuid_t      euid;       /* effective UID of the task */
    kgid_t      egid;       /* effective GID of the task */
    kuid_t      fsuid;      /* UID for VFS ops */
    kgid_t      fsgid;      /* GID for VFS ops */
    unsigned    securebits; /* SUID-less security management */
    kernel_cap_t    cap_inheritable; /* caps our children can inherit */
    kernel_cap_t    cap_permitted;  /* caps we're permitted */
    kernel_cap_t    cap_effective;  /* caps we can actually use */
    kernel_cap_t    cap_bset;   /* capability bounding set */
    kernel_cap_t    cap_ambient;    /* Ambient capability set */
#ifdef CONFIG_KEYS
    unsigned char   jit_keyring;    /* default keyring to attach requested
                     * keys to */
    struct key __rcu *session_keyring; /* keyring inherited over fork */
    struct key  *process_keyring; /* keyring private to this process */
    struct key  *thread_keyring; /* keyring private to this thread */
    struct key  *request_key_auth; /* assumed request_key authority */
#endif
#ifdef CONFIG_SECURITY
    void        *security;  /* subjective LSM security */
#endif
    struct user_struct *user;   /* real user ID subscription */
    struct user_namespace *user_ns; /* user_ns the caps and keyrings are relative to. */
    struct group_info *group_info;  /* supplementary groups for euid/fsgid */
    struct rcu_head rcu;        /* RCU deletion hook */
};
```

In this case, the size of the `cred` struct is 0xa8. Let's say we have,
`ptr = kmalloc(0xa8, 37748928LL);` and after that this region is freed i.e `kfree(ptr)`.
In case there is a UAF, new allocations of the size 0xa8 will return the previous memory region. Now, if we open a device twice, the second opening will overwrite the first allocated space if pointers to the allocated space are stored in a global variable. Thus, different file descriptors, let's say `fd1` and `fd2` would be referring to the same global variable. Thus, if we free a pointer for fd1, the same pointer for fd2 would also get freed! This UAF bug can be elevated to modify the contents of the cred struct.

Now, when a new process is spawned via the `fork()` system call, the following events occur:


```fork -> sys_clone -> do_fork -> _do_fork -> copy_process -> copy_creds -> prepare_creds -> kmem_cache_alloc ```


Now, if a region of size 0xa8 is free (for fd1), and the pointer to that region is a dangling pointer, new allocations of the same size(for fd2) will return the same pointer and thus, an arbitrary write primitive can be achieved. So, the plan of attack is to allocate a region of size equivalent to that of the cred struct(0xa8) and then free it via fd1. If the pointer is a global variable, we can create a new file descriptor fd2 , execute the fork system call to create a new process and write into the cred struct via  fd2. Set the `uid`, `gid` and some other ids to 0 and then call `system("/bin/sh")` to spawn a root shell.


You may try the following CTF challenge to get a good idea of this technique
https://github.com/AravGarg/kernel-hacking/tree/master/ctf-challs/CISC2017-BabyDriver