// BSD 3-Clause License
// Mach-O indirect symbol & arm64e PAC __auth_got rebinder for ios-mcp companion dylibs.

#include "fishhook.h"
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <mach-o/nlist.h>
#include <stdbool.h>
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

extern kern_return_t mach_vm_protect(vm_map_t target_task,
                                     mach_vm_address_t address,
                                     mach_vm_size_t size,
                                     boolean_t set_maximum,
                                     vm_prot_t new_protection);

extern kern_return_t mach_vm_region(vm_map_t target_task,
                                    mach_vm_address_t *address,
                                    mach_vm_size_t *size,
                                    vm_region_flavor_t flavor,
                                    vm_region_info_t info,
                                    mach_msg_type_number_t *infoCnt,
                                    mach_port_t *object_name);

typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64 section_t;
typedef struct nlist_64 nlist_t;

#define MCP_COMM_PAGE_TPRO_WRITE_ENABLE  ((const volatile uint64_t *)0x0fffffffc0d0ULL)
#define MCP_COMM_PAGE_TPRO_WRITE_DISABLE ((const volatile uint64_t *)0x0fffffffc0d8ULL)

static inline int mcp_tpro_enable_write(void) {
#if defined(__arm64__) || defined(__aarch64__)
    uint64_t val = *MCP_COMM_PAGE_TPRO_WRITE_ENABLE;
    if (!val) return 0;
    __asm__ volatile("msr S3_6_C15_C1_5, %0\nisb sy" :: "r"(val) : "memory");
    typedef bool (*tpro_writable_fn)(void);
    static tpro_writable_fn s_fn = NULL;
    static int s_resolved = 0;
    if (!s_resolved) {
        s_fn = (tpro_writable_fn)dlsym(RTLD_DEFAULT, "_os_thread_self_tpro_is_writeable");
        s_resolved = 1;
    }
    if (s_fn) {
        return s_fn() ? 1 : 0;
    }
    return 1;
#else
    return 0;
#endif
}

static inline void mcp_tpro_disable_write(void) {
#if defined(__arm64__) || defined(__aarch64__)
    uint64_t val = *MCP_COMM_PAGE_TPRO_WRITE_DISABLE;
    if (!val) return;
    __asm__ volatile("msr S3_6_C15_C1_5, %0\nisb sy" :: "r"(val) : "memory");
#endif
}

static uintptr_t mcp_strip_ptr(const void *ptr) {
    if (!ptr) return 0;
#if MCP_HAS_PTRAUTH
    return (uintptr_t)ptrauth_strip((void *)ptr, ptrauth_key_function_pointer);
#else
    return ((uintptr_t)ptr) & 0x00007fffffffffffULL;
#endif
}

static int mcp_page_is_writable(uintptr_t addr) {
    mach_vm_address_t region_addr = (mach_vm_address_t)addr;
    mach_vm_size_t region_size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = MACH_PORT_NULL;
    kern_return_t kr = mach_vm_region(mach_task_self(),
                                      &region_addr,
                                      &region_size,
                                      VM_REGION_BASIC_INFO_64,
                                      (vm_region_info_t)&info,
                                      &count,
                                      &obj);
    if (obj != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), obj);
    }
    if (kr != KERN_SUCCESS) return 0;
    if ((uintptr_t)region_addr > addr || addr >= (uintptr_t)(region_addr + region_size)) {
        return 0;
    }
    return ((info.protection & VM_PROT_WRITE) != 0) ? 1 : 0;
}

static int mcp_make_writable(void *addr, size_t len) {
    if (mcp_tpro_enable_write()) {
        if (mcp_page_is_writable((uintptr_t)addr)) {
            return 1;
        }
    }
    uintptr_t page_size = (uintptr_t)getpagesize();
    uintptr_t start = ((uintptr_t)addr) & ~(page_size - 1);
    uintptr_t end = (((uintptr_t)addr) + len + page_size - 1) & ~(page_size - 1);
    mach_vm_size_t span = (mach_vm_size_t)(end - start);

    kern_return_t kr = mach_vm_protect(mach_task_self(),
                                       (mach_vm_address_t)start,
                                       span,
                                       FALSE,
                                       VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        kr = mach_vm_protect(mach_task_self(),
                             (mach_vm_address_t)start,
                             span,
                             FALSE,
                             VM_PROT_READ | VM_PROT_WRITE);
    }
    if (kr != KERN_SUCCESS) {
        kr = vm_protect(mach_task_self(),
                        (vm_address_t)start,
                        (vm_size_t)span,
                        FALSE,
                        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    }
    if (kr != KERN_SUCCESS) {
        kr = vm_protect(mach_task_self(),
                        (vm_address_t)start,
                        (vm_size_t)span,
                        FALSE,
                        VM_PROT_READ | VM_PROT_WRITE);
    }
    if (mcp_page_is_writable((uintptr_t)addr)) {
        return 1;
    }
    return 0;
}

int mcp_write_raw_slot_in_proc(uintptr_t slot_addr, uintptr_t val) {
    if (!slot_addr) return 0;
    int tpro = mcp_tpro_enable_write();
    int writable = mcp_page_is_writable(slot_addr);
    if (!writable) {
        writable = mcp_make_writable((void *)slot_addr, sizeof(uintptr_t));
    }
    if (!writable) {
        if (tpro) mcp_tpro_disable_write();
        return 0;
    }
    *(uintptr_t *)slot_addr = val;
    if (tpro) mcp_tpro_disable_write();
    return 1;
}

static int mcp_compute_slot_replacement_preserving_pac(uintptr_t *slot,
                                                       uintptr_t stripped_orig,
                                                       void *replacement,
                                                       uintptr_t *out_new_val,
                                                       int *out_is_auth) {
    uintptr_t cur = *slot;
    uintptr_t stripped_repl = mcp_strip_ptr(replacement);
    if (out_is_auth) *out_is_auth = 0;

    if (cur == stripped_orig) {
        if (out_new_val) *out_new_val = stripped_repl;
        return 1;
    }
#if MCP_HAS_PTRAUTH
    void *raw_orig = (void *)stripped_orig;
    void *raw_repl = (void *)stripped_repl;
    uintptr_t cand_ia_addr = (uintptr_t)ptrauth_sign_unauthenticated(raw_orig, ptrauth_key_asia, slot);
    if (cur == cand_ia_addr) {
        if (out_new_val) *out_new_val = (uintptr_t)ptrauth_sign_unauthenticated(raw_repl, ptrauth_key_asia, slot);
        if (out_is_auth) *out_is_auth = 1;
        return 1;
    }
    uintptr_t cand_ia_zero = (uintptr_t)ptrauth_sign_unauthenticated(raw_orig, ptrauth_key_asia, 0);
    if (cur == cand_ia_zero) {
        if (out_new_val) *out_new_val = (uintptr_t)ptrauth_sign_unauthenticated(raw_repl, ptrauth_key_asia, 0);
        if (out_is_auth) *out_is_auth = 1;
        return 1;
    }
    uintptr_t cand_ib_addr = (uintptr_t)ptrauth_sign_unauthenticated(raw_orig, ptrauth_key_asib, slot);
    if (cur == cand_ib_addr) {
        if (out_new_val) *out_new_val = (uintptr_t)ptrauth_sign_unauthenticated(raw_repl, ptrauth_key_asib, slot);
        if (out_is_auth) *out_is_auth = 1;
        return 1;
    }
    uintptr_t cand_ib_zero = (uintptr_t)ptrauth_sign_unauthenticated(raw_orig, ptrauth_key_asib, 0);
    if (cur == cand_ib_zero) {
        if (out_new_val) *out_new_val = (uintptr_t)ptrauth_sign_unauthenticated(raw_repl, ptrauth_key_asib, 0);
        if (out_is_auth) *out_is_auth = 1;
        return 1;
    }
    if (mcp_strip_ptr((const void *)cur) == stripped_orig) {
        if ((cur >> 48) != 0) {
            if (out_new_val) *out_new_val = (uintptr_t)ptrauth_sign_unauthenticated(raw_repl, ptrauth_key_asia, slot);
            if (out_is_auth) *out_is_auth = 1;
        } else {
            if (out_new_val) *out_new_val = stripped_repl;
            if (out_is_auth) *out_is_auth = 0;
        }
        return 1;
    }
#else
    if ((cur >> 48) == 0 && mcp_strip_ptr((const void *)cur) == stripped_orig) {
        if (out_new_val) *out_new_val = stripped_repl;
        return 1;
    }
#endif
    return 0;
}

static void mcp_collector_record(mcp_slot_collector_t *collector,
                                 uintptr_t slot_addr,
                                 uintptr_t orig_val,
                                 uintptr_t new_val,
                                 int is_auth,
                                 int written_in_proc,
                                 const char *symbol_name,
                                 const char *section_name) {
    if (!collector) return;
    for (size_t i = 0; i < collector->count; i++) {
        if (collector->patches[i].slot_addr == slot_addr) {
            if (written_in_proc && !collector->patches[i].written_in_proc) {
                collector->patches[i].written_in_proc = 1;
            }
            return;
        }
    }
    if (collector->count >= collector->capacity) {
        size_t next_cap = collector->capacity ? (collector->capacity * 2) : 16;
        mcp_slot_patch_t *next = (mcp_slot_patch_t *)realloc(collector->patches, next_cap * sizeof(mcp_slot_patch_t));
        if (!next) return;
        collector->patches = next;
        collector->capacity = next_cap;
    }
    mcp_slot_patch_t *entry = &collector->patches[collector->count++];
    memset(entry, 0, sizeof(*entry));
    entry->slot_addr = slot_addr;
    entry->orig_val = orig_val;
    entry->new_val = new_val;
    entry->is_auth = is_auth;
    entry->written_in_proc = written_in_proc;
    if (symbol_name) {
        strncpy(entry->symbol_name, symbol_name, sizeof(entry->symbol_name) - 1);
    }
    if (section_name) {
        strncpy(entry->section_name, section_name, sizeof(entry->section_name) - 1);
    }
}

void mcp_slot_collector_free(mcp_slot_collector_t *collector) {
    if (!collector) return;
    if (collector->patches) {
        free(collector->patches);
        collector->patches = NULL;
    }
    collector->count = 0;
    collector->capacity = 0;
}

static int mcp_process_slot(uintptr_t *slot,
                            uintptr_t stripped_orig,
                            void *replacement,
                            const char *symbol_name,
                            const char *section_name,
                            mcp_slot_collector_t *collector) {
    uintptr_t orig_val = *slot;
    uintptr_t new_val = 0;
    int is_auth = 0;
    if (!mcp_compute_slot_replacement_preserving_pac(slot, stripped_orig, replacement, &new_val, &is_auth)) {
        if ((orig_val >> 48) == 0) {
            new_val = mcp_strip_ptr(replacement);
            is_auth = 0;
        } else {
            return 0;
        }
    }

    int written = 0;
    if (!collector || !collector->prepare_only) {
        written = mcp_write_raw_slot_in_proc((uintptr_t)slot, new_val);
    }
    mcp_collector_record(collector, (uintptr_t)slot, orig_val, new_val, is_auth, written, symbol_name, section_name);
    return written;
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
                                        const uint32_t *indirect_symtab,
                                        mcp_slot_collector_t *collector) {
    (void)stripped_originals;
    uint32_t *indirect_symbol_indices = (uint32_t *)(indirect_symtab + section->reserved1);
    uintptr_t *slots = (uintptr_t *)((uintptr_t)slide + section->addr);
    size_t count = section->size / sizeof(uintptr_t);
    char sect_buf[20] = {0};
    strncpy(sect_buf, section->sectname, 16);

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
                mcp_process_slot(&slots[i],
                                 cur_stripped,
                                 rebindings[j].replacement,
                                 rebindings[j].name,
                                 sect_buf,
                                 collector);
                break;
            }
        }
    }
}

static void mcp_rebind_bound_got_section(struct mcp_rebinding rebindings[],
                                         size_t rebindings_nel,
                                         const uintptr_t *stripped_originals,
                                         const section_t *section,
                                         intptr_t slide,
                                         mcp_slot_collector_t *collector) {
    uintptr_t *slots = (uintptr_t *)((uintptr_t)slide + section->addr);
    size_t count = section->size / sizeof(uintptr_t);
    char sect_buf[20] = {0};
    strncpy(sect_buf, section->sectname, 16);

    for (size_t i = 0; i < count; i++) {
        uintptr_t cur = slots[i];
        if (!cur) continue;
        uintptr_t cur_stripped = mcp_strip_ptr((const void *)cur);
        for (size_t j = 0; j < rebindings_nel; j++) {
            if (!stripped_originals[j]) continue;
            if (cur_stripped == stripped_originals[j] &&
                cur_stripped != mcp_strip_ptr(rebindings[j].replacement)) {
                mcp_process_slot(&slots[i],
                                 stripped_originals[j],
                                 rebindings[j].replacement,
                                 rebindings[j].name,
                                 sect_buf,
                                 collector);
                break;
            }
        }
    }
}

int mcp_rebind_symbols_image_collect(const struct mach_header *raw_header,
                                     intptr_t slide,
                                     const struct mach_header *self_header,
                                     struct mcp_rebinding rebindings[],
                                     size_t rebindings_nel,
                                     mcp_slot_collector_t *collector) {
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
                                                sect, slide, symtab, strtab, indirect_symtab, collector);
                }
                if (strncmp(sect->sectname, "__got", 5) == 0 ||
                    strncmp(sect->sectname, "__la_symbol_ptr", 15) == 0 ||
                    strncmp(sect->sectname, "__auth_got", 10) == 0 ||
                    strncmp(sect->sectname, "__auth_ptr", 10) == 0) {
                    mcp_rebind_bound_got_section(rebindings, rebindings_nel, stripped_originals,
                                                 sect, slide, collector);
                }
            }
        }
        cur += lc->cmdsize;
    }

    free(stripped_originals);
    return 0;
}

int mcp_rebind_symbols_image(const struct mach_header *raw_header,
                             intptr_t slide,
                             const struct mach_header *self_header,
                             struct mcp_rebinding rebindings[],
                             size_t rebindings_nel) {
    return mcp_rebind_symbols_image_collect(raw_header, slide, self_header, rebindings, rebindings_nel, NULL);
}

int mcp_rebind_symbols_filtered_collect(const struct mach_header *self_header,
                                        int (*should_hook_image)(const struct mach_header *header, const char *name),
                                        struct mcp_rebinding rebindings[],
                                        size_t rebindings_nel,
                                        mcp_slot_collector_t *collector) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const struct mach_header *hdr = _dyld_get_image_header(i);
        if (!hdr || hdr == self_header) continue;
        const char *name = _dyld_get_image_name(i);
        if (should_hook_image && !should_hook_image(hdr, name)) continue;
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        mcp_rebind_symbols_image_collect(hdr, slide, self_header, rebindings, rebindings_nel, collector);
    }
    return 0;
}

int mcp_rebind_symbols_filtered(const struct mach_header *self_header,
                                int (*should_hook_image)(const struct mach_header *header, const char *name),
                                struct mcp_rebinding rebindings[],
                                size_t rebindings_nel) {
    return mcp_rebind_symbols_filtered_collect(self_header, should_hook_image, rebindings, rebindings_nel, NULL);
}
