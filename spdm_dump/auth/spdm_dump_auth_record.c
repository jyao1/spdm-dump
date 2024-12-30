/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-dump/blob/main/LICENSE.md
 **/

#include "spdm_dump.h"

void dump_spdm_auth_record_no_tag(const void *buffer, size_t buffer_size)
{
    const spdm_auth_record_t *auth_no_tag;
    size_t payload_size;

    printf("AUTH_NO_TAG ");

    if (buffer_size < sizeof(spdm_auth_record_t) + sizeof(uint32_t)) {
        printf("\n");
        return;
    }

    auth_no_tag = buffer;
    if(auth_no_tag->auth_tag_len != 0) {
        printf("\n");
        return;
    }
    payload_size = libspdm_read_uint32((const uint8_t *)buffer + sizeof(spdm_auth_record_t));

    dump_spdm_auth_message (
        (const uint8_t *)buffer + sizeof(spdm_auth_record_t) + sizeof(uint32_t),
        payload_size);
}

void dump_spdm_auth_record_with_tag(const void *buffer, size_t buffer_size)
{
    const spdm_auth_record_t *auth_with_tag;
    const spdm_auth_record_tag_t *auth_record_tag;
    size_t payload_size;

    printf("AUTH_WITH_TAG ");

    if (buffer_size < sizeof(spdm_auth_record_t) + sizeof(spdm_auth_record_tag_t) +
                      sizeof(uint32_t)) {
        printf("\n");
        return;
    }

    auth_with_tag = buffer;
    if(auth_with_tag->auth_tag_len < sizeof(spdm_auth_record_tag_t)) {
        printf("\n");
        return;
    }

    auth_record_tag = (const void *)(auth_with_tag + 1);
    if (!m_param_quite_mode) {
        printf("(CredId=0x%04x) ", auth_record_tag->credential_id);
    }
    if (m_param_all_mode) {
        printf("\n    AuthTag(");
        dump_data((auth_record_tag + 1), auth_with_tag->auth_tag_len - sizeof(spdm_auth_record_tag_t));
        printf(")");
    }

    payload_size = libspdm_read_uint32((const uint8_t *)buffer + sizeof(spdm_auth_record_t) +
                                       auth_with_tag->auth_tag_len);

    dump_spdm_auth_message (
        (const uint8_t *)buffer + sizeof(spdm_auth_record_t) + auth_with_tag->auth_tag_len +
        sizeof(uint32_t),
        payload_size);
}
