#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "rootfs.h"
#include "fs-structs.h"
#include "log.h"
#include "elfs.h"
#include "defaultfs.h"
#include "misc.h"



/* root directory object creation */

telf_status rootfs_build(telf_ctx *ctx)
{
        telf_status ret;
        telf_obj *root_obj = NULL;
        telf_obj *sections_obj = NULL;
        telf_obj *libs_obj = NULL;
        telf_obj *header_obj = NULL;

        if (NULL == (root_obj = elf_obj_new(ctx, "/", NULL,
                                            ELF_ROOTDIR,
                                            ELF_S_IFDIR))) {
                ERR("root obj creation failed");
                ret = ELF_FAILURE;
                goto err;
        }

        if (NULL == (sections_obj = elf_obj_new(ctx, "sections", root_obj,
                                                ELF_SECTION,
                                                ELF_S_IFDIR))) {
                ERR("section obj creation failed");
                ret = ELF_FAILURE;
                goto err;
        }

        if (NULL == (libs_obj = elf_obj_new(ctx, "libs", root_obj,
                                            ELF_LIBS,
                                            ELF_S_IFDIR))) {
                ERR("libs obj creation failed");
                ret = ELF_FAILURE;
                goto err;
        }

        if (NULL == (header_obj = elf_obj_new(ctx, "header", root_obj,
                                              ELF_HEADER,
                                              ELF_S_IFDIR))) {
                ERR("header obj creation failed");
                ret = ELF_FAILURE;
                goto err;
        }

        list_add(root_obj->entries, sections_obj);
        list_add(root_obj->entries, libs_obj);
        list_add(root_obj->entries, header_obj);

        /* and finally... */
        ctx->root = root_obj;

        ret = ELF_SUCCESS;
  err:
        return ret;
}

