---
title: Creating a custom filesytem using FUSE - Part 1
readtime: true
date: 2024-06-24
tags: [linux,filesystem,low-level]
---

## Introduction
File systems are the backbone of any operating system, responsible for managing how data is stored and retrieved. Traditionally, developing a file system has been a complex and daunting task, requiring deep knowledge of kernel programming. However, with FUSE (Filesystem in Userspace), this task becomes significantly more accessible and versatile. In this blog post, we will explore what FUSE is, how it works, and why it is a game-changer for Linux users and developers alike. We'll be developing a simple filesystem that supports creating, reading, writing files and listing files in a directory. 

## About FUSE
FUSE (Filesystem in USErspace) is a software layer in Linux that allows non-privileged users to create their own file-systems without editing the kernel source code. It is made up of three main components:

1. `fuse.ko` - The FUSE kernel module, which provides the interface for FUSE.
2. `libfuse` - A userspace library which provides the necessary API for handling communication with the FUSE kernel module, allowing userspace applications to implement custom filesystem logic.
3. `fusermount` - A mount utility.

`libfuse` provides two types of APIs: a `high-level` synchronous API and a `low-level` asynchronous API. Both APIs handle incoming requests from the kernel by using callbacks to pass these requests to the main program. When using the high-level API, callbacks handle file names and paths, and the request is completed when the callback function returns. In contrast, with the low-level API, callbacks work with inodes, and you must explicitly send responses using a separate set of API functions. In this post, we'll be using the low-level API for building our filesystem. The high-level API will be taken care of in upcoming posts.

Before using the low-level API, we must know about some important structures and macros.

## Some important structures, functions and macros

1. `fuse_args`
This structure is used to handle command-line arguments passed to a FUSE filesystem.

```c
struct fuse_args {
	int argc; // number of arguments
	char **argv; // argument vector, NULL terminated
	int allocated; // is argv allocated?
};
```
2. `FUSE_ARGS_INIT`
Initializes a struct fuse_args with argc and argv, and `allocated` set to 0.

```c
#define FUSE_ARGS_INIT(argc, argv) { argc, argv, 0 }
```

3. `fuse_cmdline_opts`
A structure used to store command-line options parsed from the arguments. This structure helps manage and configure the FUSE filesystem based on user inputs.

```c
struct fuse_cmdline_opts {
	int singlethread;
	int foreground;
	int debug;
	int nodefault_subtype;
	char *mountpoint;
	int show_version;
	int show_help;
	int clone_fd;
	unsigned int max_idle_threads; 
	unsigned int max_threads; // This was added in libfuse 3.12
};
```
This structure can be populated using the `fuse_parse_cmdline` function.
```c
struct fuse_cmdline_opts opts;
fuse_parse_cmdline(&args,&opts);
```

4. `fuse_session_new`
Creates a new low-level session. This function accepts most file-system independent mount options.
```c
struct fuse_session *fuse_session_new(struct fuse_args *args,const struct fuse_lowlevel_ops *op,
size_t op_size, void *userdata);
```

5. `fuse_set_signal_handlers`
This function installs signal handlers for the signals `SIGHUP`, `SIGINT`, and `SIGTERM` that will attempt to unmount the file system. If there is already a signal handler installed for any of these signals then it is not replaced. This function returns zero on success and -1 on failure.

```c
int fuse_set_signal_handlers(struct fuse_session *se);
```

6. `fuse_lowlevel_ops`
This structure represents the low-level filesystem operations
```c
struct fuse_lowlevel_ops {
	// Called when libfuse establishes communication with the FUSE kernel module.
	void (*init) (void *userdata, struct fuse_conn_info *conn);

	// Cleans up filesystem, called on filesystem exit.
	void (*destroy) (void *userdata);

	// Look up a directory entry by name and get its attributes.
	void (*lookup) (fuse_req_t req, fuse_ino_t parent, const char *name);

	// Can be called to forget about an inode
	void (*forget) (fuse_req_t req, fuse_ino_t ino, uint64_t nlookup);

	// Called to get file attributes
	void (*getattr) (fuse_req_t req, fuse_ino_t ino,
			 struct fuse_file_info *fi);

	// Called to set file attributes
	void (*setattr) (fuse_req_t req, fuse_ino_t ino, struct stat *attr,
			 int to_set, struct fuse_file_info *fi);

	// Called to read the target of a symbolic link
	void (*readlink) (fuse_req_t req, fuse_ino_t ino);

	// Called to create a file node
	void (*mknod) (fuse_req_t req, fuse_ino_t parent, const char *name,
		       mode_t mode, dev_t rdev);

	// Called to create a directory
	void (*mkdir) (fuse_req_t req, fuse_ino_t parent, const char *name,
		       mode_t mode);

	// Called to remove a file
	void (*unlink) (fuse_req_t req, fuse_ino_t parent, const char *name);

	// Called to remove a directory
	void (*rmdir) (fuse_req_t req, fuse_ino_t parent, const char *name);

	// Called to create a symbolic link
	void (*symlink) (fuse_req_t req, const char *link, fuse_ino_t parent,
			 const char *name);

	// Called to rename a file or directory
	void (*rename) (fuse_req_t req, fuse_ino_t parent, const char *name,
			fuse_ino_t newparent, const char *newname,
			unsigned int flags);

	// Called to create a hard link
	void (*link) (fuse_req_t req, fuse_ino_t ino, fuse_ino_t newparent,
		      const char *newname);

	// Called to open a file
	void (*open) (fuse_req_t req, fuse_ino_t ino,
		      struct fuse_file_info *fi);

	// Called to read data from a file
	void (*read) (fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
		      struct fuse_file_info *fi);

	// Called to write data to a file
	void (*write) (fuse_req_t req, fuse_ino_t ino, const char *buf,
		       size_t size, off_t off, struct fuse_file_info *fi);

	// Called on each close() of the opened file, for flushing cached data
	void (*flush) (fuse_req_t req, fuse_ino_t ino,
		       struct fuse_file_info *fi);

	// Called to release an open file (when there are no more references to an open file i.e all file descriptors are closed and all memory mappings are unmapped)
	void (*release) (fuse_req_t req, fuse_ino_t ino,
			 struct fuse_file_info *fi);

	// Called to synchronize file contents
	void (*fsync) (fuse_req_t req, fuse_ino_t ino, int datasync,
		       struct fuse_file_info *fi);

	// Called to open a directory
	void (*opendir) (fuse_req_t req, fuse_ino_t ino,
			 struct fuse_file_info *fi);

	// Called to read directory entries
	void (*readdir) (fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
			 struct fuse_file_info *fi);

	// Called to release an open directory
	void (*releasedir) (fuse_req_t req, fuse_ino_t ino,
			    struct fuse_file_info *fi);

	// Called to synchronize directory contents
	void (*fsyncdir) (fuse_req_t req, fuse_ino_t ino, int datasync,
			  struct fuse_file_info *fi);

	// Called to get file system statistics
	void (*statfs) (fuse_req_t req, fuse_ino_t ino);

	// Called to set an extended attribute
	void (*setxattr) (fuse_req_t req, fuse_ino_t ino, const char *name,
			  const char *value, size_t size, int flags);

	// Called to get an extended attribute
	void (*getxattr) (fuse_req_t req, fuse_ino_t ino, const char *name,
			  size_t size);

	// Called to list extended attribute names
	void (*listxattr) (fuse_req_t req, fuse_ino_t ino, size_t size);

	// Called to remove an extended attribute
	void (*removexattr) (fuse_req_t req, fuse_ino_t ino, const char *name);

	// Called to check file-access permissions
	void (*access) (fuse_req_t req, fuse_ino_t ino, int mask);

	// Called to create and open a file
	void (*create) (fuse_req_t req, fuse_ino_t parent, const char *name,
			mode_t mode, struct fuse_file_info *fi);

	// Called to get a file lock
	void (*getlk) (fuse_req_t req, fuse_ino_t ino,
		       struct fuse_file_info *fi, struct flock *lock);

	// Called to set a file lock
	void (*setlk) (fuse_req_t req, fuse_ino_t ino,
		       struct fuse_file_info *fi,
		       struct flock *lock, int sleep);

	// Called to map a block index within file to a block index within device
	void (*bmap) (fuse_req_t req, fuse_ino_t ino, size_t blocksize,
		      uint64_t idx);

	// The ioctl handler
#if FUSE_USE_VERSION < 35
	void (*ioctl) (fuse_req_t req, fuse_ino_t ino, int cmd,
		       void *arg, struct fuse_file_info *fi, unsigned flags,
		       const void *in_buf, size_t in_bufsz, size_t out_bufsz);
#else
	void (*ioctl) (fuse_req_t req, fuse_ino_t ino, unsigned int cmd,
		       void *arg, struct fuse_file_info *fi, unsigned flags,
		       const void *in_buf, size_t in_bufsz, size_t out_bufsz);
#endif

	// Called to poll a file for I/O readiness.
	void (*poll) (fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi,
		      struct fuse_pollhandle *ph);

	// Called to write a buffer to a file.
	void (*write_buf) (fuse_req_t req, fuse_ino_t ino,
			   struct fuse_bufvec *bufv, off_t off,
			   struct fuse_file_info *fi);

	// Called to reply to a retrieve operation.
	void (*retrieve_reply) (fuse_req_t req, void *cookie, fuse_ino_t ino,
				off_t offset, struct fuse_bufvec *bufv);

	// Called to forget multiple inodes
	void (*forget_multi) (fuse_req_t req, size_t count,
			      struct fuse_forget_data *forgets);

	// Called to acquire, modify or release a file lock
	void (*flock) (fuse_req_t req, fuse_ino_t ino,
		       struct fuse_file_info *fi, int op);

	//  Called to allocate space to a file
	void (*fallocate) (fuse_req_t req, fuse_ino_t ino, int mode,
		       off_t offset, off_t length, struct fuse_file_info *fi);

	// Called to read a directory entry with attributes 
	void (*readdirplus) (fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
			 struct fuse_file_info *fi);

	// To copy a range of data from one file to another
	void (*copy_file_range) (fuse_req_t req, fuse_ino_t ino_in,
				 off_t off_in, struct fuse_file_info *fi_in,
				 fuse_ino_t ino_out, off_t off_out,
				 struct fuse_file_info *fi_out, size_t len,
				 int flags);

	// The lseek operation, for specifying new file offsets past the current end of the file.
	void (*lseek) (fuse_req_t req, fuse_ino_t ino, off_t off, int whence,
		       struct fuse_file_info *fi);
};

```

7. `fuse_session_loop`
Enter a single threaded, blocking event loop. The loop can be terminated through signals if signal handlers have been pre-registered.

```c
int fuse_session_loop(struct fuse_session *se);
```

8. `fuse_session_unmount`
This function ensures that the file system is unmounted.
```c
void fuse_session_unmount(struct fuse_session *se);
```

9. `fuse_reply_*`
These types of functions (for example, fuse_reply_entry, fuse_reply_open, etc.) are used to send responses back to the FUSE kernel module from the user space filesystem implementation. Each `fuse_reply_*` type of function corresponds to a specific type of response that can be sent, depending on the operation being performed.

## Some concepts related to filesystems
1. `Inode`
An inode (index node) is a data structure that stores essential information about a file.

2. `Inode Number`
The inode number is a unique identifier for a file or directory within a filesystem on Unix-like operating systems. When a file is created, a name and an inode number is assigned to it.

3. `Link Count`
The UNIX file system contains two entries in every directory: `.` and `..`. Thus, each directory has a link count of 2+n, where n is the number of subdirectories within that directory.

4. `Inode number of the root directory`
In our custom file system, the inode number of the root directory will be 1. However, it is 2 in case of linux. A proper explanation for the same can be found [here](https://unix.stackexchange.com/questions/198673/why-does-have-the-inode-2).


### Using the low-level API
The low-level API is primarily documented over [here](https://libfuse.github.io/doxygen/fuse__lowlevel_8h.html). In this post, we'll be using fuse3. In case you face any trouble with including the headers, install libfuse3-dev using `sudo apt install libfuse3-dev`.

We need to create some handlers, according to the items present in the struct `fuse_lowlevel_ops`, mentioned above.

1. `Creating a file` : For creating a file, we need to add corresponding functions for `lookup`, `create`, and `getattr`. In order to create a file using `touch`, we need to create a function for `setattr` as well.

2. `Reading a file` : For reading a file, we need to add corresponding functions for `lookup`, `open`, and `read`

3. `Writing to a file` : For writing data to a file, we need to add corresponding functions for `lookup`, `open`, and `write`.

4. `Listing files in a directory` : For listing files in a directory, the following sequence of events normally occur:
`getattr` -> `opendir` -> `readdir` -> `lookup`. So, we need to create corresponding handlers for all of them.


Here's the source code for all of this. I've also pushed the code into [this](https://github.com/0xsh4dy/fuse_tutorial) GitHub repo. In the next post, we'll make our file system multithreaded and add a few more functionalities, such as changing file permissions using chmod, and deleting files.

```c
// Do not forget to add the macro FUSE_USE_VERSION
#define FUSE_USE_VERSION 34

// Max 10 files can be stored in the root directory
#define MAX_FILES 10

#define MAX_FILENAME_LEN 64

#include <fuse3/fuse_lowlevel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/stat.h>

// Structure for storing information about a file in our filesystem
struct file_info
{
    size_t size; // size of the file
    char *data; // file contents
    char *name; // file name
    mode_t mode; // mode (permissions)
    ino_t ino; // inode number
    bool is_used; // is the current slot used
};

// Structure for handling directory entries
struct dirbuf
{
    char *p;
    size_t size;
};

// Storage for files
struct file_info files[MAX_FILES];

void fatal_error(const char *message)
{
    puts(message);
    exit(1);
}

// A macro for adding a new entry
#define DIRBUF_ADDENTRY(req, b, name, ino)                                                      \
    do                                                                                          \
    {                                                                                           \
        struct stat stbuf;                                                                      \
        size_t oldsize = (b)->size;                                                             \
        (b)->size += fuse_add_direntry(req, NULL, 0, name, NULL, 0);                            \
        (b)->p = (char *)realloc((b)->p, (b)->size);                                            \
        memset(&stbuf, 0, sizeof(stbuf));                                                       \
        stbuf.st_ino = ino;                                                                     \
        fuse_add_direntry(req, (b)->p + oldsize, (b)->size - oldsize, name, &stbuf, (b)->size); \
    } while (0)

#define min(x, y) ((x) < (y) ? (x) : (y))

static void init_handler(void *userdata, struct fuse_conn_info *conn)
{
    // Called when libfuse establishes communication with the FUSE kernel module.
    puts("init_handler called");
    for (int i = 0; i < MAX_FILES; i++)
    {
        files[i].data = NULL;
        files[i].mode = 0;
        files[i].size = 0;
        files[i].is_used = false;
        files[i].name = (char *)malloc(MAX_FILENAME_LEN);
        files[i].ino = 2;
    }
}

static void lookup_handler(fuse_req_t req, fuse_ino_t parent, const char *name)
{
    printf("lookup_handler called: looking for %s\n", name);
    struct fuse_entry_param e;

    memset(&e, 0, sizeof(e));

    // Ensure that the parent is the root directory
    if (parent == 1)
    {
        for (int i = 0; i < MAX_FILES; i++)
        {
            // If the file if found
            if (strcmp(files[i].name, name) == 0)
            {
                e.ino = files[i].ino;
                e.attr.st_ino = files[i].ino;
                e.attr.st_mode = files[i].mode;
                e.attr_timeout = 1.0;
                e.entry_timeout = 1.0;
                e.attr.st_nlink = 1;
                e.attr.st_size = files[i].size;
                fuse_reply_entry(req, &e);
                return;
            }
        }
    }
    // No entry found
    fuse_reply_err(req, ENOENT);
}

static void getattr_handler(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    puts("getattr_handler called");
    struct stat stbuf;

    // Is a directory (root directory of our filesystem)
    if (ino == 1)
    {
        stbuf.st_mode = S_IFDIR | 0755;
        stbuf.st_nlink = 2;
        fuse_reply_attr(req,&stbuf,1.0);
        return;
    }
    else
    {
        for(int i=0;i<MAX_FILES;i++){
            // File found, get some attributes such as mode, size and number of hardlinks
            if(files[i].ino == ino){
                stbuf.st_nlink = 1;
                stbuf.st_mode = files[i].mode;
                stbuf.st_size = files[i].size;
                fuse_reply_attr(req,&stbuf,1.0);
                return;
            }
        }

    }

    fuse_reply_err(req,ENOENT);
}


static int reply_buf_limited(fuse_req_t req, const char *buf, size_t bufsize,
                             off_t off, size_t maxsize)
{
    if (off < bufsize)
        return fuse_reply_buf(req, buf + off,
                              min(bufsize - off, maxsize));
    else
        return fuse_reply_buf(req, NULL, 0);
}

void readdir_handler(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
                     struct fuse_file_info *fi)
{
    printf("readdir_handler called with the inode number %ld\n", ino);
    (void)fi;

    // Currently there's only one directory present in our filesystem, the root directory
    if (ino != 1)
        fuse_reply_err(req, ENOTDIR);
    else
    {
        struct dirbuf b;

        memset(&b, 0, sizeof(b));
        // Add entries for . and ..
        DIRBUF_ADDENTRY(req, &b, ".", 1);
        DIRBUF_ADDENTRY(req, &b, "..", 1);

        for (int i = 0; i < MAX_FILES; i++)
        {
            if (files[i].is_used)
            {
                printf("Adding entry for filename -> %s | inode -> %ld\n", files[i].name, files[i].ino);
                DIRBUF_ADDENTRY(req, &b, files[i].name, files[i].ino);
            }
        }

        reply_buf_limited(req, b.p, b.size, off, size);
        free(b.p);
    }
}

void opendir_handler(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    puts("opendir_handler called");
    if (ino != 1)
    {
        // Inode number for the only directory right now is 1
        fuse_reply_err(req, ENOTDIR);
    }
    else
    {
        fuse_reply_open(req, fi);
    }
}

static void open_handler(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
    puts("open_handler called");
    if (ino < 2)
    {
        // Inode number 1, i.e a directory
        fuse_reply_err(req, EISDIR);
    }
    else
    {
        // Open the file
        fuse_reply_open(req, fi);
    }
}

static void create_handler(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, struct fuse_file_info *fi)
{
    struct fuse_entry_param e;
    memset(&e, 0, sizeof(e));

    printf("create_handler called with the filename as %s and mode as %d\n", name, mode);

    if (parent != 1)
    {
        // The root directory is the parent of all files
        fuse_reply_err(req, ENOENT);
        return;
    }

    for (int i = 0; i < MAX_FILES; i++)
    {
        if (files[i].is_used == false)
        {
            files[i].is_used = true;
            files[i].mode = S_IFREG | mode;
            files[i].size = 0x0;
            files[i].data = NULL;
            files[i].ino = i + 2;
            strncpy(files[i].name, name, strlen(name));
            files[i].name[strlen(name)] = 0x0;

            e.ino = i + 2; // the inode number of the root directory of our filesystem is 1.
            e.attr.st_ino = i + 2;
            e.attr.st_mode = S_IFREG | mode;
            e.attr.st_nlink = 1;
            e.attr.st_size = 0x0;

            fuse_reply_create(req, &e, fi);
            return;
        }
    }
    fuse_reply_err(req, ENOSPC);
}

static void read_handler(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi)
{
    printf("read_handler called for the file with inode number %ld\n", ino);
    if (ino < 2)
    {
        fuse_reply_err(req, EISDIR);
    }
    else
    {
        for (int i = 0; i < MAX_FILES; i++)
        {
            if (files[i].ino == ino)
            {
                reply_buf_limited(req, files[i].data, files[i].size, off, size);
                return;
            }
        }
        fuse_reply_err(req, ENOENT);
    }
}

static void write_handler(fuse_req_t req, fuse_ino_t ino, const char *buf, size_t size, off_t off, struct fuse_file_info *fi)
{
    printf("write_handler called on the file with inode number %ld\n", ino);
    printf("offset = %lu and size=%zu\n", off, size);
    if (ino < 2)
    {
        fuse_reply_err(req, EISDIR);
    }
    else
    {
        for (int i = 0; i < MAX_FILES; i++)
        {
            if (files[i].ino == ino)
            {
                if (files[i].size == 0)
                {
                    files[i].data = malloc(size + off);
                }
                else
                {
                    files[i].data = realloc(files[i].data, off + size);
                }
                files[i].size = off + size;
                memcpy(files[i].data + off, buf, size);
                fuse_reply_write(req, size);
                return;
            }
        }
    }
}


static void setattr_handler(fuse_req_t req, fuse_ino_t ino, struct stat *attr, int to_set, struct fuse_file_info *fi)
{
    puts("setattr_handler called");
    struct stat stbuf;

    if (ino < 2)
    {
        fuse_reply_err(req, EISDIR);
        return;
    }
    for (int i = 0; i < MAX_FILES; i++)
    {
        if (files[i].ino == ino)
        {
            stbuf.st_ino = ino;
            stbuf.st_mode = files[i].mode;
            stbuf.st_nlink = 1;
            stbuf.st_size = files[i].size;

            if (to_set & FUSE_SET_ATTR_ATIME)
            {
                stbuf.st_atime = attr->st_atime;
            }
            if (to_set & FUSE_SET_ATTR_MTIME)
            {
                stbuf.st_mtime = attr->st_mtime;
            }
            if (to_set & FUSE_SET_ATTR_CTIME)
            {
                stbuf.st_ctime = attr->st_ctime;
            }
            fuse_reply_attr(req, &stbuf, 1.0);
            return;
        }
    }
}

static struct fuse_lowlevel_ops operations = {
    .lookup = lookup_handler,
    .init = init_handler,
    .open = open_handler,
    .read = read_handler,
    .create = create_handler,
    .write = write_handler,
    .getattr = getattr_handler,
    .setattr = setattr_handler,
    .opendir = opendir_handler,
    .readdir = readdir_handler,
};

int main(int argc, char **argv)
{
    int retval = 0;
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct fuse_cmdline_opts opts;
    struct fuse_session *se;

    if (fuse_parse_cmdline(&args, &opts))
    {
        return 1;
    }
    if (opts.show_help)
    {
        printf("Usage: %s [options] <mountpoint>\n", argv[0]);
        fuse_cmdline_help();
        return 0;
    }
    if (opts.show_version)
    {
        fuse_lowlevel_version();
        return 0;
    }
    if (opts.mountpoint == NULL)
    {
        printf("Usage: %s [options] <mountpoint>\n", argv[0]);
        return 1;
    }

    se = fuse_session_new(&args, &operations, sizeof(operations), NULL);
    if (se == NULL)
    {
        free(opts.mountpoint);
        fuse_opt_free_args(&args);
        return 1;
    }

    if (fuse_set_signal_handlers(se) != 0)
    {
        retval = 1;
        goto errlabel_two;
    }

    if (fuse_session_mount(se, opts.mountpoint) != 0)
    {
        retval = 1;
        goto errlabel_one;
    }

    fuse_session_loop(se);

    fuse_session_unmount(se);
errlabel_one:
    fuse_remove_signal_handlers(se);

errlabel_two:
    fuse_session_destroy(se);
    free(opts.mountpoint);
    fuse_opt_free_args(&args);
    return retval;
}
```

Compile it using `gcc fileName.c -o fileName -lfuse3`

![](/images/fuse/fuse_01.png)

References:

https://github.com/libfuse

https://github.com/osxfuse/fuse/blob/master/README.md

https://libfuse.github.io/doxygen/hello__ll_8c.html
