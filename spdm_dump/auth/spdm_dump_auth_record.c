/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-dump/blob/main/LICENSE.md
 **/

#include "spdm_dump.h"

void dump_spdm_auth_record_with_tag(const void *buffer, size_t buffer_size)
{
    const spdm_auth_record_type_msg_with_auth_t *auth_with_tag;
    const spdm_auth_record_tag_t *auth_record_tag;
    size_t payload_size;

    printf("AUTH_WITH_TAG ");

    if (buffer_size < sizeof(spdm_auth_record_t) +
                      sizeof(spdm_auth_record_type_msg_with_auth_t) +
                      sizeof(spdm_auth_record_tag_t) +
                      sizeof(uint32_t)) {
        printf("\n");
        return;
    }

    auth_with_tag = buffer;
    if(auth_with_tag->auth_tag_len < sizeof(spdm_auth_record_tag_t)) {
        printf("\n");
        return;
    }
    if (!m_param_quite_mode) {
        printf("(AuthRecId=0x%08x) ", auth_with_tag->auth_rec_id);
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

    if (buffer_size < sizeof(spdm_auth_record_t) +
                      sizeof(spdm_auth_record_type_msg_with_auth_t) +
                      auth_with_tag->auth_tag_len +
                      sizeof(uint32_t)) {
        printf("\n");
        return;
    }

    payload_size = libspdm_read_uint32((const uint8_t *)buffer + sizeof(spdm_auth_record_t) +
                                       sizeof(spdm_auth_record_type_msg_with_auth_t) +
                                       auth_with_tag->auth_tag_len);

    if (buffer_size < sizeof(spdm_auth_record_t) +
                      sizeof(spdm_auth_record_type_msg_with_auth_t) +
                      auth_with_tag->auth_tag_len +
                      sizeof(uint32_t) + payload_size) {
        printf("\n");
        return;
    }

    dump_spdm_auth_message (
        (const uint8_t *)buffer + sizeof(spdm_auth_record_t) +
        sizeof(spdm_auth_record_type_msg_with_auth_t) +
        auth_with_tag->auth_tag_len +
        sizeof(uint32_t),
        payload_size);
}

void dump_spdm_auth_record_error(const void *buffer, size_t buffer_size)
{
    const spdm_auth_record_type_record_error_t *auth_record_error;
    size_t payload_size;

    printf("AUTH_RECORD_ERROR ");

    if (buffer_size < sizeof(spdm_auth_record_t) +
                      sizeof(spdm_auth_record_type_record_error_t)) {
        printf("\n");
        return;
    }

    auth_record_error = buffer;
    if (!m_param_quite_mode) {
        printf("(AuthRecId=0x%08x) ", auth_record_error->error_auth_rec_id);
    }

    payload_size = buffer_size - sizeof(spdm_auth_record_t) -
                   sizeof(auth_record_error->error_auth_rec_id);
    dump_spdm_auth_message (
        &auth_record_error->auth_rec_error_info,
        payload_size);
}

void dump_spdm_auth_record_type_auth_message(const void *buffer, size_t buffer_size)
{
    const spdm_auth_record_t *auth_record;

    printf("AUTH_RECORD_TYPE_AUTH_MESSAGE");

    if (buffer_size < sizeof(spdm_auth_record_t)) {
        printf("\n");
        return;
    }

    auth_record = buffer;
    if (buffer_size < sizeof(spdm_auth_record_t) + auth_record->payload_len) {
        printf("\n");
        return;
    }

    dump_spdm_auth_message (
        (const uint8_t *)buffer + sizeof(spdm_auth_record_t),
        auth_record->payload_len);
}

void dump_spdm_auth_record_type_message_with_auth(const void *buffer, size_t buffer_size)
{
    const spdm_auth_record_t *auth_record;

    printf("AUTH_RECORD_TYPE_MESSAGE_WITH_AUTH");

    if (buffer_size < sizeof(spdm_auth_record_t)) {
        printf("\n");
        return;
    }

    auth_record = buffer;
    if (buffer_size < sizeof(spdm_auth_record_t) + auth_record->payload_len) {
        printf("\n");
        return;
    }

    dump_spdm_auth_record_with_tag (
        (const uint8_t *)buffer + sizeof(spdm_auth_record_t),
        auth_record->payload_len);
}

void dump_spdm_auth_record_type_record_error(const void *buffer, size_t buffer_size)
{
    const spdm_auth_record_t *auth_record;

    printf("AUTH_RECORD_TYPE_RECORD_ERROR");

    if (buffer_size < sizeof(spdm_auth_record_t)) {
        printf("\n");
        return;
    }

    auth_record = buffer;
    if (buffer_size < sizeof(spdm_auth_record_t) + auth_record->payload_len) {
        printf("\n");
        return;
    }

    dump_spdm_auth_record_error (
        (const uint8_t *)buffer + sizeof(spdm_auth_record_t),
        auth_record->payload_len);
}
