#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "sectionfs.h"
#include "fs-structs.h"
#include "log.h"
#include "elfs.h"
#include "sectionfs.h"
#include "defaultfs.h"
#include "symbolfs.h"
#include "fsapi.h"


/* section directory object creation */

telf_status sectionfs_build(telf_ctx *ctx)
{
        telf_status ret, rc;
        telf_obj *sections_obj = NULL;

        ElfW(Shdr) *sh_strtab = ctx->shdr + ctx->ehdr->e_shstrndx;
        unsigned char *sh_strtab_p = ctx->addr + sh_strtab->sh_offset;

        if (ELF_SUCCESS != (rc = elf_namei(ctx, "/sections", &sections_obj))) {
                ERR("can't find any section entry: %s", elf_status_to_str(rc));
                ret = ELF_ENOENT;
                goto end;
        }

        ctx->n_sections = ctx->ehdr->e_shnum;

        if (! ctx->n_sections)
                return ELF_SUCCESS;

        for (int i = 0; i < ctx->n_sections; ++i) {
                ElfW(Shdr) *shdr = ctx->shdr + i;
                telf_type type;
                char name[128];
                unsigned char *s_name = sh_strtab_p + shdr->sh_name;
                telf_obj *obj = NULL;

                if (! *s_name)
                        /* empty name, use the section address */
                        sprintf(name, "noname.%p", sh_strtab + i);
                else
                        /* we want to convert '.bss', etc to 'bss', etc*/
                        sprintf(name, "%s",
                                '.' == *s_name ? s_name + 1 : s_name);

                switch (ctx->shdr[i].sh_type) {
#define MAP(x) case SHT_##x: type = ELF_SECTION_##x; break
                        MAP(NULL);
                        MAP(DYNSYM);
                        MAP(SYMTAB);
                        MAP(NOBITS);
                        MAP(PROGBITS);
                        MAP(DYNAMIC);
                        MAP(HASH);
                        MAP(NOTE);
                        MAP(REL);
                        MAP(RELA);
                        MAP(STRTAB);
#undef MAP
                default:
                        ERR("unknown object type: 0x%x", shdr->sh_type);
                        type = ELF_SECTION_OTHER;
                        break;
                }

                if (NULL == (obj = elf_obj_new(ctx, name, sections_obj, type,
                                               ELF_S_IFDIR))) {
                        ERR("obj '%s' creation failed", name);
                        ret = ELF_FAILURE;
                        goto end;
                }

                if (SHF_WRITE & shdr->sh_flags)
                        obj->st.mode |= ELF_S_IWUSR;
                if (SHF_ALLOC & shdr->sh_flags)
                        obj->st.mode |= ELF_S_IRUSR;
                if (SHF_EXECINSTR & shdr->sh_flags)
                        obj->st.mode |= ELF_S_IXUSR;

                list_add(sections_obj->entries, obj);
        }

        ret = ELF_SUCCESS;
  end:
        return ret;
}
