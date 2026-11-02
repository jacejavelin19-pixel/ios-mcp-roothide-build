// BSD 3-Clause License
// Mach-O indirect symbol & arm64e PAC __auth_got rebinder for ios-mcp companion dylibs.

#include "fishhook.h"
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <mach-o/nlist.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#if defined(__arm64e__) || (__has_feature(ptrauth_calls))
#include <ptrauth.h>
#define MCP_HAS_PTRAUTH 1
#else
#define MCP_HAS_PTRAUTH 0
#endif

#ifndef SEG_DATA_CONST
#define SEG_DATA_CONST "__DATA_CONST"
#endif
#ifndef SEG_AUTH_CONST
#define SEG_AUTH_CONST "__AUTH_CONST"
#endif
#ifndef SEG_AUTH
#define SEG_AUTH "__AUTH"
#endif

typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64 section_t;
typedef struct nlist_64 nlist_t;

static uintptr_t mcp_strip_ptr(const void *ptr) {
    if (!ptr) return 0;
#if MCP_HAS_PTRAUTH
    return (uintptr_t)ptrauth_strip((void *)ptr, ptrauth_key_function_pointer);
#else
    return ((uintptr_t)ptr) & 0x00007fffffffffffULL;
#endif
}

static int mcp_make_writable(void *addr, size_t len) {
    uintptr_t page_size = (uintptr_t)getpagesize();
    uintptr_t start = ((uintptr_t)addr) & ~(page_size - 1);
    uintptr_t end = (((uintptr_t)addr) + len + page_size - 1) & ~(page_size - 1);
    kern_return_t kr = vm_protect(mach_task_self(),
                                  (vm_address_t)start,
                                  (vm_size_t)(end - start),
                                  FALSE,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        kr = vm_protect(mach_task_self(),
                        (vm_address_t)start,
                        (vm_size_t)(end - start),
                        FALSE,
                        VM_PROT_READ | VM_PROT_WRITE);
    }
    return (kr == KERN_SUCCESS) ? 1 : 0;
}

static int mcp_write_slot_preserving_pac(uintptr_t *slot,
                                         uintptr_t stripped_orig,
                                         void *replacement) {
    uintptr_t cur = *slot;
    uintptr_t stripped_repl = mcp_strip_ptr(replacement);
    if (cur == stripped_orig) {
        if (!mcp_make_writable(slot, sizeof(uintptr_t))) return 0;
        *slot = stripped_repl;
        return 1;
    }
#if MCP_HAS_PTRAUTH
    void *raw_orig = (void *)stripped_orig;
    void *raw_repl = (void *)stripped_repl;
    uintptr_t cand_ia_addr = (uintptr_t)ptrauth_sign_unauthenticated(raw_orig, ptrauth_key_asia, slot);
    if (cur == cand_ia_addr) {
        if (!mcp_make_writable(slot, sizeof(uintptr_t))) return 0;
        *slot = (uintptr_t)ptrauth_sign_unauthenticated(raw_repl, ptrauth_key_asia, slot);
        return 1;
    }
    uintptr_t cand_ia_zero = (uintptr_t)ptrauth_sign_unauthenticated(raw_orig, ptrauth_key_asia, 0);
    if (cur == cand_ia_zero) {
        if (!mcp_make_writable(slot, sizeof(uintptr_t))) return 0;
        *slot = (uintptr_t)ptrauth_sign_unauthenticated(raw_repl, ptrauth_key_asia, 0);
        return 1;
    }
    uintptr_t cand_ib_addr = (uintptr_t)ptrauth_sign_unauthenticated(raw_orig, ptrauth_key_asib, slot);
    if (cur == cand_ib_addr) {
        if (!mcp_make_writable(slot, sizeof(uintptr_t))) return 0;
        *slot = (uintptr_t)ptrauth_sign_unauthenticated(raw_repl, ptrauth_key_asib, slot);
        return 1;
    }
#endif
    return 0;
}

static void mcp_resolve_originals(struct mcp_rebinding rebindings[],
                                  size_t rebindings_nel,
                                  uintptr_t *stripped_originals) {
    for (size_t i = 0; i < rebindings_nel; i++) {
        void *sym = dlsym(RTLD_DEFAULT, rebindings[i].name);
        stripped_originals[i] = mcp_strip_ptr(sym);
        if (sym && rebindings[i].replaced && *rebindings[i].replaced == NULL) {
            *rebindings[i].replaced = sym;
        }
    }
}

static void mcp_rebind_indirect_section(struct mcp_rebinding rebindings[],
                                        size_t rebindings_nel,
                                        const uintptr_t *stripped_originals,
                                        const section_t *section,
                                        intptr_t slide,
                                        const nlist_t *symtab,
                                        const char *strtab,
                                        const uint32_t *indirect_symtab) {
    uint32_t *indirect_symbol_indices = (uint32_t *)(indirect_symtab + section->reserved1);
    uintptr_t *slots = (uintptr_t *)((uintptr_t)slide + section->addr);
    size_t count = section->size / sizeof(uintptr_t);

    for (size_t i = 0; i < count; i++) {
        uint32_t symtab_index = indirect_symbol_indices[i];
        if (symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL ||
            symtab_index == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) {
            continue;
        }
        uint32_t strtab_offset = symtab[symtab_index].n_un.n_strx;
        const char *symbol_name = strtab + strtab_offset;
        if (!symbol_name[0] || !symbol_name[1]) continue;

        for (size_t j = 0; j < rebindings_nel; j++) {
            if (strcmp(&symbol_name[1], rebindings[j].name) == 0) {
                uintptr_t cur = slots[i];
                uintptr_t cur_stripped = mcp_strip_ptr((const void *)cur);
                if (cur_stripped == mcp_strip_ptr(rebindings[j].replacement)) {
                    break;
                }
                if (rebindings[j].replaced && *rebindings[j].replaced == NULL && cur != 0) {
#if MCP_HAS_PTRAUTH
                    *rebindings[j].replaced = ptrauth_sign_unauthenticated((void *)cur_stripped,
                                                                           ptrauth_key_function_pointer,
                                                                           0);
#else
                    *rebindings[j].replaced = (void *)cur;
#endif
                }
                uintptr_t orig_target = stripped_originals[j] ? stripped_originals[j] : cur_stripped;
                if (!mcp_write_slot_preserving_pac(&slots[i], orig_target, rebindings[j].replacement)) {
                    // Unbound lazy slot fallback (unauthenticated pointer slot only)
                    if ((cur >> 48) == 0 && mcp_make_writable(&slots[i], sizeof(uintptr_t))) {
                        slots[i] = mcp_strip_ptr(rebindings[j].replacement);
                    }
                }
                break;
            }
        }
    }
}

static void mcp_rebind_bound_got_section(struct mcp_rebinding rebindings[],
                                         size_t rebindings_nel,
                                         const uintptr_t *stripped_originals,
                                         const section_t *section,
                                         intptr_t slide) {
    uintptr_t *slots = (uintptr_t *)((uintptr_t)slide + section->addr);
    size_t count = section->size / sizeof(uintptr_t);
    for (size_t i = 0; i < count; i++) {
        uintptr_t cur = slots[i];
        if (!cur) continue;
        uintptr_t cur_stripped = mcp_strip_ptr((const void *)cur);
        for (size_t j = 0; j < rebindings_nel; j++) {
            if (!stripped_originals[j]) continue;
            if (cur_stripped == stripped_originals[j] &&
                cur_stripped != mcp_strip_ptr(rebindings[j].replacement)) {
                mcp_write_slot_preserving_pac(&slots[i], stripped_originals[j], rebindings[j].replacement);
                break;
            }
        }
    }
}

int mcp_rebind_symbols_image(const struct mach_header *raw_header,
                             intptr_t slide,
                             const struct mach_header *self_header,
                             struct mcp_rebinding rebindings[],
                             size_t rebindings_nel) {
    if (!raw_header || raw_header == self_header || !rebindings || rebindings_nel == 0) {
        return -1;
    }
    if (raw_header->magic != MH_MAGIC_64) {
        return -1;
    }
    const mach_header_t *header = (const mach_header_t *)raw_header;

    uintptr_t *stripped_originals = (uintptr_t *)calloc(rebindings_nel, sizeof(uintptr_t));
    if (!stripped_originals) return -1;
    mcp_resolve_originals(rebindings, rebindings_nel, stripped_originals);

    const segment_command_t *linkedit_segment = NULL;
    const struct symtab_command *symtab_cmd = NULL;
    const struct dysymtab_command *dysymtab_cmd = NULL;

    uintptr_t cur = (uintptr_t)header + sizeof(mach_header_t);
    for (uint32_t i = 0; i < header->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cur;
        if (lc->cmd == LC_SEGMENT_64) {
            const segment_command_t *seg = (const segment_command_t *)lc;
            if (strcmp(seg->segname, SEG_LINKEDIT) == 0) {
                linkedit_segment = seg;
            }
        } else if (lc->cmd == LC_SYMTAB) {
            symtab_cmd = (const struct symtab_command *)lc;
        } else if (lc->cmd == LC_DYSYMTAB) {
            dysymtab_cmd = (const struct dysymtab_command *)lc;
        }
        cur += lc->cmdsize;
    }

    const nlist_t *symtab = NULL;
    const char *strtab = NULL;
    const uint32_t *indirect_symtab = NULL;
    int in_dyld_cache = ((header->flags & 0x80000000U) != 0);
    if (!in_dyld_cache && linkedit_segment && symtab_cmd && dysymtab_cmd && dysymtab_cmd->nindirectsyms > 0) {
        uintptr_t linkedit_base = (uintptr_t)slide + linkedit_segment->vmaddr - linkedit_segment->fileoff;
        symtab = (const nlist_t *)(linkedit_base + symtab_cmd->symoff);
        strtab = (const char *)(linkedit_base + symtab_cmd->stroff);
        indirect_symtab = (const uint32_t *)(linkedit_base + dysymtab_cmd->indirectsymoff);
    }

    cur = (uintptr_t)header + sizeof(mach_header_t);
    for (uint32_t i = 0; i < header->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)cur;
        if (lc->cmd == LC_SEGMENT_64) {
            const segment_command_t *seg = (const segment_command_t *)lc;
            if (strcmp(seg->segname, SEG_DATA) != 0 &&
                strcmp(seg->segname, SEG_DATA_CONST) != 0 &&
                strcmp(seg->segname, SEG_AUTH) != 0 &&
                strcmp(seg->segname, SEG_AUTH_CONST) != 0) {
                cur += lc->cmdsize;
                continue;
            }
            for (uint32_t j = 0; j < seg->nsects; j++) {
                const section_t *sect = (const section_t *)((uintptr_t)seg + sizeof(segment_command_t)) + j;
                uint8_t stype = sect->flags & SECTION_TYPE;
                if ((stype == S_LAZY_SYMBOL_POINTERS || stype == S_NON_LAZY_SYMBOL_POINTERS) &&
                    symtab && strtab && indirect_symtab) {
                    mcp_rebind_indirect_section(rebindings, rebindings_nel, stripped_originals,
                                                sect, slide, symtab, strtab, indirect_symtab);
                }
                if (strncmp(sect->sectname, "__got", 5) == 0 ||
                    strncmp(sect->sectname, "__la_symbol_ptr", 15) == 0 ||
                    strncmp(sect->sectname, "__auth_got", 10) == 0 ||
                    strncmp(sect->sectname, "__auth_ptr", 10) == 0) {
                    mcp_rebind_bound_got_section(rebindings, rebindings_nel, stripped_originals, sect, slide);
                }
            }
        }
        cur += lc->cmdsize;
    }

    free(stripped_originals);
    return 0;
}

int mcp_rebind_symbols_filtered(const struct mach_header *self_header,
                                int (*should_hook_image)(const struct mach_header *header, const char *name),
                                struct mcp_rebinding rebindings[],
                                size_t rebindings_nel) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const struct mach_header *hdr = _dyld_get_image_header(i);
        if (!hdr || hdr == self_header) continue;
        const char *name = _dyld_get_image_name(i);
        if (should_hook_image && !should_hook_image(hdr, name)) continue;
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        mcp_rebind_symbols_image(hdr, slide, self_header, rebindings, rebindings_nel);
    }
    return 0;
}
