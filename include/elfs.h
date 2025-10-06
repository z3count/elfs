#ifndef ELFS_H
#define ELFS_H

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __FreeBSD__
#include <limits.h>
#else
#include <linux/limits.h>
#endif
#include <sys/ptrace.h>

#include <pthread.h>
#include <elf.h>
#include <link.h>

#include "fs-structs.h"
#include "list.h"

struct self_ctx;


typedef struct {
        char *buf;
        size_t buf_len;
} telf_default_content;


typedef telf_status (* tobj_fillcontent_func)(void *, char **, size_t *);
typedef void (* tobj_freecontent_func)(void *);
typedef telf_status (* tobj_release_func)(void *);

typedef struct {
        char *str;
        tobj_fillcontent_func fillcontent_func;
        tobj_freecontent_func freecontent_func;
        tobj_release_func     release_func;
} telf_fcb;

typedef struct {
        pid_t pid;
        char *mountpoint;
        char *binfile;
} telf_options;

typedef struct self_obj {
        telf_fs_driver *driver;  /* set of fs callbacks */

        tobj_fillcontent_func fill_func;
        tobj_freecontent_func free_func;

        struct self_ctx *ctx;    /* global context */
        struct self_obj *parent; /* equivalent to ".." */

        char *name;              /* entry name */
        void *data;              /* a pointer to the symbol for example */
        telf_type type;          /* type of elf object */
        telf_stat st;            /* our own struct stat */
        tlist *entries;          /* if directory: list of entries */

        uint32_t refcount;

        pthread_mutex_t lock;
} telf_obj;

typedef struct self_ctx {
        telf_fs_driver *driver;  /* set of fs callbacks */

        int loglevel;

        pthread_mutex_t lock;
        int lock_init;

        struct stat st;
        char binpath[PATH_MAX];
        unsigned char *addr;
        pid_t pid;

        ElfW(Ehdr) *ehdr;       /* elf header */
        ElfW(Shdr) *shdr;       /* sections header */
        ElfW(Phdr) *phdr;       /* program header */
        ElfW(Addr) base_vaddr;  /* the virtual base address */
        int n_sections;         /* number of sections */

        tlist *libpath;         /* paths where libs are located */

        ElfW(Sym) *symtab;      /* symbol table */
        int n_syms;
        char *strtab;           /* string table */

        ElfW(Sym) *dsymtab;     /* dynamic symbol table */
        int n_dsyms;
        char *dstrtab;          /* dynamic string table */

        telf_obj *root;         /* fs entry point: root directory */
} telf_ctx;



telf_status elf_namei(telf_ctx *, const char *, telf_obj **objp);

telf_fcb *elf_get_fcb(telf_fcb *fcb, int n_fcb, char *ident);
telf_obj *elf_obj_new(telf_ctx *, char *, telf_obj *, telf_type, telf_ftype);
void elf_obj_free(telf_obj *obj);

void elf_ctx_lock(telf_ctx *ctx);
void elf_ctx_unlock(telf_ctx *ctx);

void elf_obj_lock(telf_obj *obj);
void elf_obj_unlock(telf_obj *obj);

void elf_obj_ref_nolock(telf_obj *obj);
void elf_obj_ref(telf_obj *obj);
void elf_obj_unref_nolock(telf_obj *obj);
void elf_obj_unref(telf_obj *obj);

#endif /* ELFS_H */
