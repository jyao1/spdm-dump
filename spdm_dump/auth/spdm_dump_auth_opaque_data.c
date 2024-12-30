/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-dump/blob/main/LICENSE.md
 **/

#include "spdm_dump.h"

void dump_spdm_auth_aods_invoke_seap(const void *buffer, size_t buffer_size)
{
    const spdm_auth_aods_invoke_seap_t *aods;

    if (buffer_size < sizeof(spdm_auth_aods_invoke_seap_t)) {
        return;
    }

    printf("INVOKE_SEAP ");

    aods = buffer;
    printf("(P=%02x,CredId=0x%04x)", aods->presence_extension, aods->credential_id);
}

void dump_spdm_auth_aods_seap_invoked(const void *buffer, size_t buffer_size)
{
    const spdm_auth_aods_seap_invoked_t *aods;

    if (buffer_size < sizeof(spdm_auth_aods_seap_invoked_t)) {
        return;
    }

    printf("SEAP_INVOKED ");

    aods = buffer;
    printf("(P=%02x)", aods->presence_extension);
}

void dump_spdm_auth_aods_seap_success(const void *buffer, size_t buffer_size)
{
    const spdm_auth_aods_seap_success_t *aods;

    if (buffer_size < sizeof(spdm_auth_aods_seap_success_t)) {
        return;
    }

    printf("SEAP_SUCCESS ");

    aods = buffer;
    printf("(P=%02x)", aods->presence_extension);
}

void dump_spdm_auth_aods_auth_hello(const void *buffer, size_t buffer_size)
{
    const spdm_auth_aods_auth_hello_t *aods;

    if (buffer_size < sizeof(spdm_auth_aods_auth_hello_t)) {
        return;
    }

    printf("AUTH_HELLO ");

    aods = buffer;
    printf("(P=%02x)", aods->presence_extension);
}

dispatch_table_entry_t m_spdm_auth_aods_opaque_dispatch[] = {
    { SPDM_AUTH_AODS_ID_INVOKE_SEAP,
      "INVOKE_SEAP", dump_spdm_auth_aods_invoke_seap },
    { SPDM_AUTH_AODS_ID_SEAP_INVOKED,
      "SEAP_INVOKED", dump_spdm_auth_aods_seap_invoked },
    { SPDM_AUTH_AODS_ID_SEAP_SUCCESS,
      "SEAP_SUCCESS", dump_spdm_auth_aods_seap_success },
    { SPDM_AUTH_AODS_ID_AUTH_HELLO,
      "AUTH_HELLO", dump_spdm_auth_aods_auth_hello },
};

void dump_spdm_dmtf_dsp_opaque_data(const void *buffer, size_t buffer_size)
{

    const spdm_auth_aods_table_header_t *aods_table_header;
    const spdm_auth_aods_header_t *aods_element;

    aods_table_header = buffer;

    if (aods_table_header->vendor_id_len != 2) {
        return ;
    }

    printf("\n      OpaqueElement(id=0x%02x, vendor_id=0x%04x, len=0x%04x) ",
           aods_table_header->id,
           aods_table_header->dmtf_spec_id,
           aods_table_header->opaque_element_data_len);

    if (aods_table_header->dmtf_spec_id != 289) {
        return ;
    }
    if (aods_table_header->opaque_element_data_len < sizeof(spdm_auth_aods_header_t)) {
        return ;
    }

    aods_element = (const void *)(aods_table_header + 1);
    printf("Element(id=0x%02x) ",
           aods_element->aods_id);

    dump_dispatch_message(
        m_spdm_auth_aods_opaque_dispatch,
        LIBSPDM_ARRAY_SIZE(m_spdm_auth_aods_opaque_dispatch),
        aods_element->aods_id,
        (uint8_t *)aods_element,
        aods_table_header->opaque_element_data_len);
}
