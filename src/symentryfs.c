#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include "log.h"
#include "symentryfs.h"
#include "misc.h"
#include "elfs.h"
#include "defaultfs.h"

#include "compat.h"

static void symentryfs_freecontent(void *data)
{
        telf_default_content *content = data;

        if (! content)
                return;

        free(content->buf);
        free(content);
}

static telf_status symentryfs_read_asmcode(void *obj_hdl, char **bufp,
                                           size_t *buf_lenp)
{
        telf_obj *obj = obj_hdl;
        telf_status ret, rc;
        ElfW(Sym) *sym = obj->parent->data;
        char *buf = NULL;
        size_t buf_len = 0;
        size_t offset;

        if (STT_FUNC == ELF32_ST_TYPE(sym->st_info) && sym->st_size) {
                offset = sym->st_value - obj->ctx->base_vaddr;
                if (ELF_SUCCESS != (rc = binary_to_asm(obj->ctx->binpath,
                                                       (char *) obj->ctx->base_vaddr + offset,
                                                       sym->st_size, &buf,
                                                       &buf_len))) {
                        ERR("can't extract asm code from binary: %s",
                            elf_status_to_str(rc));
                        ret = rc;
                        goto end;
                }
        }

        ret = ELF_SUCCESS;
  end:
        if (bufp)
                *bufp = buf;
        else
                free(buf);

        if (buf_lenp)
                *buf_lenp = buf_len;

        return ret;
}

static telf_status symentryfs_read_bincode(void *obj_hdl, char **bufp,
                                           size_t *buf_lenp)
{
        telf_obj *obj = obj_hdl;
        telf_status ret;
        ElfW(Sym) *sym = obj->parent->data;
        char *buf = NULL;
        size_t buf_len = 0;
        size_t offset;

        if (STT_FUNC == ELF32_ST_TYPE(sym->st_info) && sym->st_size) {
                buf_len = sym->st_size;
                offset = sym->st_value - obj->ctx->base_vaddr;
                if (NULL == (buf = malloc(buf_len))) {
                        ERR("malloc: %m");
                        ret = ELF_ENOMEM;
                        goto end;
                }
                memcpy(buf, obj->ctx->addr + offset, sym->st_size);
        }

        ret = ELF_SUCCESS;
  end:
        if (bufp)
                *bufp = buf;
        else
                free(buf);

        if (buf_lenp)
                *buf_lenp = buf_len;

        return ret;
}

static telf_status symentryfs_read_info(void *obj_hdl, char **bufp,
                                        size_t *buf_lenp)
{
        telf_obj *obj = obj_hdl;
        char *symname = NULL;
        char *buf = NULL;
        size_t buf_len = 0;
        telf_status ret;
        FILE *out = NULL;
        ElfW(Sym) *sym = obj->parent->data;

        /* default value */
        symname = "NONAME";

        if (sym->st_name) {
                symname = ((ELF_SECTION_SYMTAB == obj->parent->type) ?
                           elf_getsymname :
                           elf_getdsymname)(obj->ctx, sym);

                if (! symname || ! *symname)
                        symname = "UNRESOLVED";
        }

        if (NULL == (out = open_memstream(&buf, &buf_len))) {
                ERR("open_memstream: %m");
                ret = ELF_ENOMEM;
                goto end;
        }

        fprintf(out,
                "value: %p\n"
                "size: %zu\n"
                "type: %s\n"
                "bind: %s\n"
                "name: %s\n",
                (void *) sym->st_value,
                sym->st_size,
                sym_type_to_str(sym),
                sym_bind_to_str(sym),
                symname);

        ret = ELF_SUCCESS;
  end:
        if (out)
                fclose(out);

        if (bufp)
                *bufp = buf;
        else
                free(buf);

        if (buf_lenp)
                *buf_lenp = buf_len;

        return ret;
}


static telf_fcb symentryfs_fcb[] = {
        { "code.bin", symentryfs_read_bincode, symentryfs_freecontent, NULL },
        { "code.asm", symentryfs_read_asmcode, symentryfs_freecontent, NULL },
        { "info",     symentryfs_read_info,    symentryfs_freecontent, NULL },
};


telf_status symentryfs_build(telf_ctx *ctx, telf_obj *parent)
{
        telf_obj *entry = NULL;

        for (size_t i = 0; i < N_ELEMS(symentryfs_fcb); i++) {
                telf_fcb *fcb = symentryfs_fcb + i;

                if (NULL == (entry = elf_obj_new(ctx, fcb->str, parent,
                                                 ELF_SYMBOL_ENTRY,
                                                 ELF_S_IFREG))) {
                        ERR("can't build entry '%s'", fcb->str);
                        continue;
                }

                entry->free_func = fcb->freecontent_func;
                entry->fill_func = fcb->fillcontent_func;
                list_add(parent->entries, entry);
        }

        return ELF_SUCCESS;
}
