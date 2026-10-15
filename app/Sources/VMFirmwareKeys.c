/* Public firmware key catalog. Copyright (c) 2026 j0shua-SYSON. MIT licensed.
 * Facts transcribed from The Apple Wiki, revision 206002 (2024-01-23):
 * https://theapplewiki.com/index.php?title=Keys:SUNorthstarTwo_8A293_(iPhone1,2)&oldid=206002
 * Only the three components used by S5LBox are listed. Rootfs uses the published
 * AES+HMAC blob; its per-block IV is derived by the DMG reader, not a fixed IV.
 * Add builds as separate records with independent identity and boot validation.
 */
#include "VMFirmwareKeys.h"
#include <string.h>

typedef struct {
    const char *product, *version, *build, *board, *platform;
    const char *kernel_key, *kernel_iv, *tree_key, *tree_iv, *root_key;
} public_keys_t;

static const public_keys_t catalog[] = {
    { "iPhone1,2", "4.0", "8A293", "n82ap", "s5l8900x",
      "3861ea3f4b0e926552e6407fb33047ff", "0182586ff40f56d59148020a5660a3c2",
      "16e89af7c2de01c82ad0ff35c9aafce1", "d80c4925442c069c64b72829f0b0261e",
      "09e054a8dd6c11c7f41ad9e614a8d564aa7d0c653585f29c0b07d1f0a1e1dc0040624a16" }
};

const char *vm_fw_public_keys_source(void) {
    return "https://theapplewiki.com/index.php?title=Keys:SUNorthstarTwo_8A293_(iPhone1,2)&oldid=206002";
}

bool vm_fw_resolve_public_keys(const vm_fw_report_t *id, vm_fw_keys_t *out) {
    if (!id || !out || !id->manifest_read) return false;
    for (size_t i = 0; i < sizeof catalog / sizeof catalog[0]; ++i) {
        const public_keys_t *record = &catalog[i];
        if (strcmp(id->product_type, record->product) ||
            strcmp(id->product_version, record->version) ||
            strcmp(id->build, record->build) || strcmp(id->board, record->board) ||
            strcmp(id->platform, record->platform)) continue;
        vm_fw_keys_t keys;
        vm_fw_keys_clear(&keys);
        bool valid = vm_fw_keys_set_img3(&keys, VM_FW_KERNEL,
                         record->kernel_key, record->kernel_iv) == VM_FW_OK &&
                     vm_fw_keys_set_img3(&keys, VM_FW_DEVICE_TREE,
                         record->tree_key, record->tree_iv) == VM_FW_OK &&
                     vm_fw_keys_set_root(&keys, record->root_key) == VM_FW_OK;
        if (valid) *out = keys;
        vm_fw_keys_clear(&keys);
        return valid;
    }
    return false;
}
