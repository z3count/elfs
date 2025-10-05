#include <limits.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/statvfs.h>
#include <libgen.h>
#include <sys/mman.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/wait.h>

#include <signal.h>

#define SYSLOG_NAMES
#include "log.h"

#include "elfs.h"
#include "misc.h"
#include "defaultfs.h"
#include "programfs.h"
#include "symbolfs.h"
#include "rootfs.h"
#include "sectionfs.h"
#include "fsapi.h"
#include "libfs.h"
#include "headerfs.h"

#ifdef __FreeBSD__
#define PTRACE_DETACH PT_DETACH
#define PTRACE_ATTACH PT_ATTACH
#include <sys/wait.h>
#endif

telf_ctx *ctx = NULL;

#define MAP(v) X(v, #v)
#define X(a, b) b,
char *elf_type_names[] = {
        ELF_TYPES_TABLE
};
#undef X
#undef MAP


telf_fcb *elf_get_fcb(telf_fcb *fcb, int n_fcb, char *ident)
{
        telf_fcb *current = NULL;
        int i;

        for (i = 0; i < n_fcb; i++) {
                current = fcb + i;

                if (0 == strcmp(ident, current->str))
                        return current;
        }

        return NULL;
}


struct fuse_operations elf_fs_ops = {
        .getattr     = elf_fs_getattr,
        .mkdir       = elf_fs_mkdir,
        .write       = elf_fs_write,
        .readdir     = elf_fs_readdir,
        .opendir     = elf_fs_opendir,
        .unlink      = elf_fs_unlink,
        .rmdir       = elf_fs_rmdir,
        .statfs      = elf_fs_statfs,
        .read        = elf_fs_read,
        .release     = elf_fs_release,
        .open        = elf_fs_open,
        .fsync       = elf_fs_fsync,
        .setxattr    = elf_fs_setxattr,
        .create      = elf_fs_create,
        .chmod       = elf_fs_chmod,
        .chown       = elf_fs_chown,
        .mknod       = elf_fs_mknod,
        .readlink    = elf_fs_readlink,
        .symlink     = elf_fs_symlink,
        .rename      = elf_fs_rename,
        .getxattr    = elf_fs_getxattr,
        .listxattr   = elf_fs_listxattr,
        .removexattr = elf_fs_removexattr,
        .truncate    = elf_fs_truncate,
        .utime       = elf_fs_utime,
        .flush       = elf_fs_flush,
        .fsyncdir    = elf_fs_fsyncdir,
        .init        = elf_fs_init,
        // .destroy     = elf_fs_destroy,
        .access      = elf_fs_access,
        .releasedir  = elf_fs_releasedir,
        .ftruncate   = elf_fs_ftruncate,
        .lock        = elf_fs_lock,
        .utimens     = elf_fs_utimens,
        .bmap        = elf_fs_bmap,
#if 0
        .iotcl       = elf_fs_ioctl,
        .poll        = elf_fs_poll,
#endif
        .getdir      = NULL, /* deprecated */
        .link        = NULL, /* no support needed */
};


static void elf_options_init(telf_options *options)
{
        options->pid = 0;
        options->mountpoint = NULL;
        options->binfile = NULL;
}

static char * elf_type_to_str(telf_type type)
{
        return elf_type_names[type];
}

void elf_obj_free(telf_obj *obj)
{
        DEBUG("free obj @%p, name=%s", (void *) obj, obj->name);

        if (obj->free_func)
                obj->free_func(obj->data);

        list_free(obj->entries);
        free(obj->name);
        free(obj->driver);
        free(obj);
}

void elf_ctx_lock(telf_ctx *ctx)
{
        pthread_mutex_lock(&ctx->lock);
}

void elf_ctx_unlock(telf_ctx *ctx)
{
        pthread_mutex_unlock(&ctx->lock);
}

void elf_obj_lock(telf_obj *obj)
{
        (void) obj;
        /* pthread_mutex_lock(&obj->lock); */
}

void elf_obj_unlock(telf_obj *obj)
{
        (void) obj;
        /* pthread_mutex_unlock(&obj->lock); */
}

static void elf_obj_free_func(void *value)
{
        elf_obj_free((telf_obj *) value);
}

static int elf_obj_cmp_func(void *key_, void *elem_)
{
        char *key = key_;
        telf_obj *elem = elem_;

        return strcmp(key, elem->name);
}

void elf_obj_ref_nolock(telf_obj *obj)
{
        obj->refcount++;
}

void elf_obj_ref(telf_obj *obj)
{
        elf_obj_lock(obj);
        elf_obj_ref_nolock(obj);
        elf_obj_unlock(obj);
}

void elf_obj_unref_nolock(telf_obj *obj)
{
        assert(obj->refcount > 0);
        obj->refcount--;
}

void elf_obj_unref(telf_obj *obj)
{
        elf_obj_lock(obj);
        elf_obj_unref_nolock(obj);
        elf_obj_unlock(obj);
}

telf_obj * elf_obj_new(telf_ctx *ctx, char *path, telf_obj *parent,
            telf_type type, /* from elf pov: SECTION, SYMBOL, ... */
            telf_ftype ftype) /* from fs pov: directory, regular, ... */
{
        telf_obj *obj = NULL;

        DEBUG("build object: path=%s, parent=%p, type=%s",
            path, (void *) parent, elf_type_to_str(type));

        if (NULL == (obj = calloc(1, sizeof *obj))) {
                ERR("malloc: %m");
                goto err;
        }

        if (NULL == (obj->name = strdup(path))) {
                ERR("strdup(%s): %m", path);
                goto err;
        }

        obj->refcount = 0;
        obj->ctx = ctx;
        obj->parent = parent;
        obj->type = type;

        if (ELF_S_ISDIR(ftype)) {
                obj->st.mode |= ELF_S_IFDIR;
                if (NULL == (obj->entries = list_new())) {
                        ERR("can't create list entries");
                        goto err;
                }

                list_set_free_func(obj->entries, elf_obj_free_func);
                list_set_cmp_func(obj->entries, elf_obj_cmp_func);
        } else {
                obj->st.mode |= ELF_S_IFREG;
        }

        if (NULL == (obj->driver = defaultfs_driver_new())) {
                ERR("can't create defaultfs driver");
                goto err;
        }

        pthread_mutex_init(&obj->lock, NULL);
        return obj;
  err:
        elf_obj_free(obj);

        return NULL;
}

static void elf_ctx_free(telf_ctx *ctx)
{
        if (! ctx)
                return;

        free(ctx->driver);

        if (ctx->lock_init)
                pthread_mutex_destroy(&ctx->lock);

        if (-1 == ctx->pid && ctx->addr)
                (void) munmap((void *) ctx->addr, ctx->st.st_size);

        if (ctx->root)
                elf_obj_free(ctx->root);

        if (ctx->pid) {
                if (ptrace(PTRACE_DETACH, ctx->pid, NULL, NULL) < 0) {
                        ERR("ptrace_detach: %s", strerror(errno));
                }

                free(ctx->ehdr);
                free(ctx->shdr);
                free(ctx->phdr);
        }

        list_free(ctx->libpath);
        free(ctx);
}

static telf_status elf_sanity_check(unsigned char *addr)
{
        telf_status ret;

        if (strncmp((const char *) addr, ELFMAG, SELFMAG))
                ERR("bad magic: %*s", SELFMAG, addr);

        if (ELFCLASSNONE == addr + EI_CLASS) {
                ERR("bad elf class %c", addr[EI_CLASS]);
                ret = ELF_FAILURE;
                goto end;
        }

        ret = ELF_SUCCESS;
  end:
        return ret;
}

static void elf_compute_base_vaddr(telf_ctx *ctx)
{
        /*
         * ELF format, chapter 2, section "program header",
         * subsection "base address"
         *
         * To compute the base address, one determines the
         * memory address associated with the lowest p_vaddr value for a
         * PT_LOAD segment. One then obtains the base address by truncating
         * the memory address to the nearest multiple of the maximum page
         * size.
         */

        int i;
        unsigned long min_vaddr = ~0;

        for (i = 0; i < ctx->ehdr->e_phnum; i++) {
                ElfW(Phdr) *phdr = ctx->phdr + i;

                if (PT_LOAD != phdr->p_type)
                        continue;

                if (phdr->p_vaddr < min_vaddr)
                        min_vaddr = phdr->p_vaddr;
        }

        ctx->base_vaddr = (min_vaddr & ~(sysconf(_SC_PAGESIZE) -1));

        DEBUG("base virtual address: %p", (void *) ctx->base_vaddr);
}

static telf_status elf_set_headers(telf_ctx *ctx)
{
        telf_status ret;

        ctx->ehdr = (ElfW(Ehdr) *) ctx->addr;
        ctx->shdr = (ElfW(Shdr) *) (ctx->addr + ctx->ehdr->e_shoff);
        ctx->phdr = (ElfW(Phdr) *) (ctx->addr + ctx->ehdr->e_phoff);

        ret = ELF_SUCCESS;
        return ret;
}

static telf_status elf_mmap_internal(telf_ctx *ctx)
{
        int fd = -1;
        telf_status ret, rc;
        void *addr = NULL;
        int mmap_flags;
        int open_flags;

        if (-1 == ctx->pid) {
                mmap_flags = PROT_READ | PROT_WRITE;
                open_flags = O_RDWR;
        } else {
                mmap_flags = PROT_READ;
                open_flags = O_RDONLY;
        }

        if ((fd = open(ctx->binpath, open_flags)) < 0) {
                ERR("open '%s': %m", ctx->binpath);
                ret = ELF_FAILURE;
                goto err;
        }

        if (MAP_FAILED == (addr = mmap(NULL, ctx->st.st_size, mmap_flags,
                                       MAP_SHARED, fd, 0))) {
                ERR("mmap: %m");
                ret = ELF_FAILURE;
                goto err;
        }

        ctx->addr = (unsigned char *) addr;

        if (ELF_SUCCESS != (rc = elf_sanity_check(ctx->addr))) {
                ERR("sanity checks failed: %s", elf_status_to_str(rc));
                ret = ELF_FAILURE;
                goto err;
        }

        DEBUG("elf header: %p", addr);

        ret = ELF_SUCCESS;
  err:
        if (fd >= 0)
                (void) close(fd);

        return ret;
}

static telf_ctx *elf_ctx_new(telf_options *opt)
{
        telf_ctx *ctx = NULL;
        telf_status rc;

        DEBUG("mount file '%s' on '%s'",
            opt->binfile, opt->mountpoint);

        if (NULL == (ctx = calloc(1, sizeof *ctx))) {
                ERR("malloc: %m");
                goto err;
        }

        if (NULL == (ctx->driver = defaultfs_driver_new())) {
                ERR("driver allocation failed");
                goto err;
        }

        pthread_mutex_init(&ctx->lock, NULL);
        ctx->lock_init = 1;

        /* create the mountpoint if it doesn't exist with 0755 creds */
        mode_t m = S_IRWXU | S_IRGRP|S_IXGRP | S_IROTH|S_IXOTH;
        if (mkdir(opt->mountpoint, m) < 0 && EEXIST != errno) {
                ERR("mkdir(%s): %m", opt->mountpoint);
                goto err;
        }

        if (opt->pid) {
                char *path;
                ssize_t len;

                if (asprintf(&path, "/proc/%d/exe", opt->pid) < 0) {
                        ERR("asprintf(): %m");
                        goto err;
                }

                if ((len = readlink(path, ctx->binpath,
                                    sizeof ctx->binpath -1)) < 0) {
                        ERR("readlink: %m");
                        free(path);
                        goto err;
                }
                free(path);

                ctx->binpath[len] = 0;
                ctx->pid = opt->pid;

                if (ptrace(PTRACE_ATTACH, ctx->pid, NULL, NULL) < 0) {
                        ERR("ptrace: %m");
                        goto err;
                }

                DEBUG("pid %d attached", ctx->pid);
                waitpid(ctx->pid, NULL, WUNTRACED);
        } else {
                if (NULL == realpath(opt->binfile, ctx->binpath)) {
                        ERR("realpath(%s): %m", opt->binfile);
                        goto err;
                }
        }

        if (stat(ctx->binpath, &ctx->st) < 0) {
                ERR("stat(%s): %m", opt->binfile);
                goto err;
        }

        if (ELF_SUCCESS != (rc = elf_mmap_internal(ctx))) {
                ERR("can't mmap() file in memory: %s", elf_status_to_str(rc));
                goto err;
        }

        if (ELF_SUCCESS != (rc = elf_set_headers(ctx))) {
                ERR("can't set elf header: %s", elf_status_to_str(rc));
                goto err;
        }

        elf_compute_base_vaddr(ctx);

        if (ELF_SUCCESS != (rc = rootfs_build(ctx))) {
                ERR("rootfs build failed: %s", elf_status_to_str(rc));
                goto err;
        }

        rc = sectionfs_build(ctx);
        if (ELF_SUCCESS != rc && ELF_ENOENT != rc) {
                ERR("sections build failed: %s", elf_status_to_str(rc));
                goto err;
        }

        /* now that 'generic' sections are built, initialize
         * specific ones */
        rc = symbolfs_build(ctx);
        if (ELF_SUCCESS != rc && ELF_ENOENT != rc) {
                ERR("symbolfs build failed: %s", elf_status_to_str(rc));
                goto err;
        }

        if (ELF_SUCCESS != (rc = programfs_build(ctx))) {
                ERR("programfs build failed: %s", elf_status_to_str(rc));
                goto err;
        }

        rc = libfs_build(ctx);
        if (ELF_SUCCESS != rc && ELF_ENOENT != rc) {
                ERR("libfs build failed: %s", elf_status_to_str(rc));
                goto err;
        }

        if (ELF_SUCCESS != (rc = headerfs_build(ctx))) {
                ERR("headerfs build failed; %s", elf_status_to_str(rc));
                goto err;
        }

        return ctx;
  err:
        elf_ctx_free(ctx);
        return NULL;
}

static void usage(const char * const prog)
{
        printf("Usage: %s [BINPATH | -p PID] [-d] MOUNTPOINT\n", prog);
        printf("\tBINPATH\t\tpath to elf binary...\n");
        printf("\t-p PID\t\trunning process we want to inspect\n");
        printf("\tMOUNTPOINT\tthe directory you want to use as mount point.\n");
        printf("\t\t\tThe directory must exist\n");
}

static int atopriority(char *str)
{
        for (int i = 0; NULL != prioritynames[i].c_name; i++) {
                if (! strcasecmp(prioritynames[i].c_name, str))
                        return prioritynames[i].c_val;
        }

        return -1;
}

static int elf_parse_commandline(int argc, char **argv, telf_options *options,
                                 int *offsetp)
{
        int ret = -1;
        int offset = 1;

        if (argc < 3)
                goto err;

        if (NULL == (options->mountpoint = strdup(argv[argc - 1]))) {
                perror("strdup");
                goto err;
        }

        if (0 == strcmp("-p", argv[1])) {
                /* we need an extra parameter, the pid */
                if (argc < 4)
                        goto err;

                offset++;
                options->pid = strtoul(argv[2], NULL, 0);
        } else {
                if (NULL == (options->binfile = strdup(argv[1]))) {
                        perror("strdup");
                        goto err;
                }
        }

        ret = 0;
  err:
        if (offsetp)
                *offsetp = offset;

        return ret;
}

int main(int argc, char **argv)
{
        int ret = EXIT_FAILURE;
        const char * const progname = argv[0];
        char *l = NULL;
        telf_options options;
        int offset = 0;

        openlog(basename((char *) progname), LOG_CONS | LOG_NOWAIT | LOG_PID, LOG_USER);

        elf_options_init(&options);

        if (elf_parse_commandline(argc, argv, &options, &offset) < 0) {
                usage(progname);
                goto end;
        }

        argc -= offset;
        argv += offset;

        // default value
        loglevel = LOG_ERR;

        if ((l = getenv("ELFS_LOGLEVEL"))) {
                int rc = atopriority(l);
                if (rc >= 0)
		      loglevel = rc;
        }

        signal(SIGHUP, SIG_IGN);
        signal(SIGURG, SIG_IGN);

        if (NULL == (ctx = elf_ctx_new(&options))) {
                ERR("ctx creation failed");
                exit(EXIT_FAILURE);
        }

        struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
        ret = fuse_main(args.argc, args.argv, &elf_fs_ops, ctx);
  end:
        closelog();

        if (ctx)
                elf_ctx_free(ctx);

        return ret;
}

