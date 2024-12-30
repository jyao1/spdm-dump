/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-dump/blob/main/LICENSE.md
 **/

#include "spdm_dump.h"

dispatch_table_entry_t m_spdm_auth_recrod_dispatch[] = {
    { SPDM_AUTH_RECORD_TYPE_NO_AUTH_TAG, "NO_AUTH_TAG", dump_spdm_auth_record_no_tag },
    { SPDM_AUTH_RECORD_TYPE_WITH_AUTH_TAG, "AUTG_TAG", dump_spdm_auth_record_with_tag },
};

void dump_spdm_vendor_dmtf_dsp(const void *buffer, size_t buffer_size)
{
    const spdm_auth_vendor_defined_header_t *vendor_defined_auth_header;
    const spdm_auth_record_t *auth_record_header;

    printf("DMTF_DSP ");

    if (buffer_size < sizeof(spdm_auth_vendor_defined_header_t)) {
        printf("\n");
        return;
    }
    vendor_defined_auth_header = buffer;

    if (!m_param_quite_mode) {
        printf("(vendor_id=0x%04x) ",
               vendor_defined_auth_header->dmtf_spec_id);
    }

    if (vendor_defined_auth_header->len !=
        sizeof(vendor_defined_auth_header->dmtf_spec_id)) {
        printf("\n");
        return;
    }
    if (vendor_defined_auth_header->dmtf_spec_id != 289) {
        printf("\n");
        return;
    }

    if (vendor_defined_auth_header->payload_length <
        sizeof(spdm_auth_record_t)) {
        printf("\n");
        return;
    }
    auth_record_header = (const void *)(vendor_defined_auth_header + 1);

    if (vendor_defined_auth_header->dmtf_spec_id == 289) {
        dump_dispatch_message(
            m_spdm_auth_recrod_dispatch,
            LIBSPDM_ARRAY_SIZE(m_spdm_auth_recrod_dispatch),
            auth_record_header->type,
            (uint8_t *)auth_record_header,
            vendor_defined_auth_header->payload_length);
    }
    if (m_param_dump_hex) {
        printf("  DMTF_DSP Vendor message:\n");
        dump_hex(buffer, buffer_size);
    }
}
