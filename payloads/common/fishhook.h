// BSD 3-Clause License (adapted for arm64 / arm64e __DATA_CONST & __auth_got on iOS 15-18+)
#ifndef MCP_FISHHOOK_H
#define MCP_FISHHOOK_H

#include <stddef.h>
#include <stdint.h>
#include <mach-o/loader.h>

#ifdef __cplusplus
extern "C" {
#endif

struct mcp_rebinding {
    const char *name;
    void *replacement;
    void **replaced;
};

typedef struct mcp_slot_patch {
    uintptr_t slot_addr;
    uintptr_t orig_val;
    uintptr_t new_val;
    int is_auth;
    int written_in_proc;
    char symbol_name[64];
    char section_name[20];
} mcp_slot_patch_t;

typedef struct mcp_slot_collector {
    mcp_slot_patch_t *patches;
    size_t count;
    size_t capacity;
    int prepare_only;
} mcp_slot_collector_t;

/// Rebind symbols in a specific Mach-O image (`header` + `slide`).
/// Safely skips `self_header` and uses TPRO + `mach_vm_protect(..., VM_PROT_COPY)` for `__DATA_CONST` / `__AUTH_CONST`.
int mcp_rebind_symbols_image(const struct mach_header *header,
                             intptr_t slide,
                             const struct mach_header *self_header,
                             struct mcp_rebinding rebindings[],
                             size_t rebindings_nel);

/// Rebind symbols in a specific Mach-O image and collect all matched GOT/lazy/auth slots.
/// When `collector->prepare_only` is non-zero, computes PAC-signed replacement values without writing in-process.
int mcp_rebind_symbols_image_collect(const struct mach_header *header,
                                     intptr_t slide,
                                     const struct mach_header *self_header,
                                     struct mcp_rebinding rebindings[],
                                     size_t rebindings_nel,
                                     mcp_slot_collector_t *collector);

/// Rebind symbols across currently loaded images matching `should_hook_image(header, image_name)`.
int mcp_rebind_symbols_filtered(const struct mach_header *self_header,
                                int (*should_hook_image)(const struct mach_header *header, const char *name),
                                struct mcp_rebinding rebindings[],
                                size_t rebindings_nel);

/// Rebind symbols across currently loaded images and collect all matched GOT/lazy/auth slots.
int mcp_rebind_symbols_filtered_collect(const struct mach_header *self_header,
                                        int (*should_hook_image)(const struct mach_header *header, const char *name),
                                        struct mcp_rebinding rebindings[],
                                        size_t rebindings_nel,
                                        mcp_slot_collector_t *collector);

/// Attempt to write an 8-byte raw value to `slot_addr` in-process (toggling TPRO / mach_vm_protect).
/// Returns 1 if written in-process, 0 if the page remains read-only.
int mcp_write_raw_slot_in_proc(uintptr_t slot_addr, uintptr_t val);

void mcp_slot_collector_free(mcp_slot_collector_t *collector);

#ifdef __cplusplus
}
#endif

#endif // MCP_FISHHOOK_H
