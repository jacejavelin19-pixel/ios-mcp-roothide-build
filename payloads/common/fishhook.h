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

/// Rebind symbols in a specific Mach-O image (`header` + `slide`).
/// Safely skips `self_header` and uses `vm_protect(..., VM_PROT_COPY)` for `__DATA_CONST` / `__AUTH_CONST`.
int mcp_rebind_symbols_image(const struct mach_header *header,
                             intptr_t slide,
                             const struct mach_header *self_header,
                             struct mcp_rebinding rebindings[],
                             size_t rebindings_nel);

/// Rebind symbols across currently loaded images matching `should_hook_image(header, image_name)`.
int mcp_rebind_symbols_filtered(const struct mach_header *self_header,
                                int (*should_hook_image)(const struct mach_header *header, const char *name),
                                struct mcp_rebinding rebindings[],
                                size_t rebindings_nel);

#ifdef __cplusplus
}
#endif

#endif // MCP_FISHHOOK_H
