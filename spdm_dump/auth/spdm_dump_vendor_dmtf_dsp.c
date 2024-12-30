/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-dump/blob/main/LICENSE.md
 **/

#include "spdm_dump.h"

dispatch_table_entry_t m_spdm_auth_recrod_dispatch[] = {
    { SPDM_AUTH_RECORD_TYPE_AUTH_MESSAGE, "AUTH_RECORD_TYPE_AUTH_MESSAGE", dump_spdm_auth_record_type_auth_message },
    { SPDM_AUTH_RECORD_TYPE_MESSAGE_WITH_AUTH, "AUTH_RECORD_TYPE_MESSAGE_WITH_AUTH", dump_spdm_auth_record_type_message_with_auth },
    { SPDM_AUTH_RECORD_TYPE_RECORD_ERROR, "AUTH_RECORD_TYPE_RECORD_ERROR", dump_spdm_auth_record_type_record_error },
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

    dump_dispatch_message(
        m_spdm_auth_recrod_dispatch,
        LIBSPDM_ARRAY_SIZE(m_spdm_auth_recrod_dispatch),
        auth_record_header->auth_record_type,
        (uint8_t *)auth_record_header,
        vendor_defined_auth_header->payload_length - sizeof(spdm_auth_record_t));

    if (m_param_dump_hex) {
        printf("  DMTF_DSP Vendor message:\n");
        dump_hex(buffer, buffer_size);
    }
}
