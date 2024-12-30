/**
 *  Copyright Notice:
 *  Copyright 2021-2022 DMTF. All rights reserved.
 *  License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/spdm-dump/blob/main/LICENSE.md
 **/

#include "spdm_dump.h"

void dump_spdm_auth_get_auth_version(const void *buffer, size_t buffer_size)
{
    printf("GET_AUTH_VERSION ");

    if (buffer_size < sizeof(spdm_auth_get_auth_version_request_t)) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
    }

    printf("\n");
}

void dump_spdm_auth_auth_version(const void *buffer, size_t buffer_size)
{
    const spdm_auth_auth_version_response_t *auth_response;
    spdm_auth_version_number_t *auth_version_number;
    size_t index;

    printf("AUTH_VERSION ");

    if (buffer_size < sizeof(spdm_auth_auth_version_response_t)) {
        printf("\n");
        return;
    }
    auth_response = buffer;
    if (buffer_size < sizeof(spdm_auth_auth_version_response_t) +
                      auth_response->version_number_entry_count *
                      sizeof(spdm_auth_version_number_t)) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        auth_version_number =
            (void *)((size_t)buffer + sizeof(spdm_auth_auth_version_response_t));
        printf("(");
        for (index = 0;
             index < auth_response->version_number_entry_count;
             index++) {
            if (index != 0) {
                printf(", ");
            }
            printf("%d.%d.%d.%d",
                   (auth_version_number[index] >> 12) & 0xF,
                   (auth_version_number[index] >> 8) & 0xF,
                   (auth_version_number[index] >> 4) & 0xF,
                   auth_version_number[index] & 0xF);
        }
        printf(") ");
    }
    printf("\n");
}

void dump_spdm_auth_select_auth_version(const void *buffer, size_t buffer_size)
{
    const spdm_auth_select_auth_version_request_t *auth_request;

    printf("SELECT_AUTH_VERSION ");

    if (buffer_size < sizeof(spdm_auth_select_auth_version_request_t)) {
        printf("\n");
        return;
    }
    auth_request = buffer;

    if (!m_param_quite_mode) {
        printf("(%d.%d) ",
            (auth_request->auth_version >> 4) & 0xF,
            auth_request->auth_version & 0xF);
    }

    printf("\n");
}

void dump_spdm_auth_select_auth_version_rsp(const void *buffer, size_t buffer_size)
{
    printf("SELECT_AUTH_VERSION_RSP ");

    if (buffer_size < sizeof(spdm_auth_select_auth_version_rsp_response_t)) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
    }

    printf("\n");
}

void dump_spdm_auth_set_cred_id_params(const void *buffer, size_t buffer_size)
{
    printf("SET_CRED_ID_PARAMS ");

    if (buffer_size < sizeof(spdm_auth_set_cred_id_params_request_t)) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
    }

    printf("\n");
}

void dump_spdm_auth_set_cred_id_params_done(const void *buffer, size_t buffer_size)
{
    printf("SET_CRED_ID_PARAMS_DONE ");

    if (buffer_size < sizeof(spdm_auth_set_cred_id_params_done_response_t)) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
    }

    printf("\n");
}

void dump_spdm_auth_get_cred_id_params(const void *buffer, size_t buffer_size)
{
    printf("GET_CRED_ID_PARAMS ");

    if (buffer_size < sizeof(spdm_auth_get_cred_id_params_request_t)) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
    }

    printf("\n");
}

void dump_spdm_auth_cred_id_params(const void *buffer, size_t buffer_size)
{
    printf("CRED_ID_PARAMS ");

    if (buffer_size < sizeof(spdm_auth_cred_id_params_response_t)) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
    }

    printf("\n");
}

void dump_spdm_auth_set_auth_policy(const void *buffer, size_t buffer_size)
{
    printf("SET_AUTH_POLICY ");

    if (buffer_size < sizeof(spdm_auth_set_auth_policy_request_t)) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
    }

    printf("\n");
}

void dump_spdm_auth_set_auth_policy_done(const void *buffer, size_t buffer_size)
{
    printf("SET_AUTH_POLICY_DONE ");

    if (buffer_size < sizeof(spdm_auth_set_auth_policy_done_response_t)) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
    }

    printf("\n");
}

void dump_spdm_auth_get_auth_policy(const void *buffer, size_t buffer_size)
{
    printf("GET_AUTH_POLICY ");

    if (buffer_size < sizeof(spdm_auth_get_auth_policy_request_t)) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
    }

    printf("\n");
}

void dump_spdm_auth_auth_policy(const void *buffer, size_t buffer_size)
{
    printf("AUTH_POLICY ");

    if (buffer_size < sizeof(spdm_auth_auth_policy_response_t)) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
    }

    printf("\n");
}

void dump_spdm_auth_start_auth(const void *buffer, size_t buffer_size)
{
    printf("START_AUTH ");

    if (buffer_size < sizeof(spdm_auth_start_auth_request_t)) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
    }

    printf("\n");
}

void dump_spdm_auth_start_auth_rsp(const void *buffer, size_t buffer_size)
{
    printf("START_AUTH_RSP ");

    if (buffer_size < sizeof(spdm_auth_start_auth_rsp_response_t)) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
    }

    printf("\n");
}

void dump_spdm_auth_end_auth(const void *buffer, size_t buffer_size)
{
    printf("END_AUTH ");

    if (buffer_size < sizeof(spdm_auth_end_auth_request_t)) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
    }

    printf("\n");
}

void dump_spdm_auth_end_auth_rsp(const void *buffer, size_t buffer_size)
{
    printf("END_AUTH_RSP ");

    if (buffer_size < sizeof(spdm_auth_end_auth_rsp_response_t)) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
    }

    printf("\n");
}

void dump_spdm_auth_elevate_privilege(const void *buffer, size_t buffer_size)
{
    printf("ELEVATE_PRIVILEGE ");

    if (buffer_size < sizeof(spdm_auth_elevate_privilege_request_t)) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
    }

    printf("\n");
}

void dump_spdm_auth_privilege_elevated(const void *buffer, size_t buffer_size)
{
    printf("PRIVILEGE_ELEVATED ");

    if (buffer_size < sizeof(spdm_auth_privilege_elevated_response_t)) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
    }

    printf("\n");
}

void dump_spdm_auth_end_elevated_privilege(const void *buffer, size_t buffer_size)
{
    printf("END_ELEVATED_PRIVILEGE ");

    if (buffer_size < sizeof(spdm_auth_end_elevated_privilege_request_t)) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
    }

    printf("\n");
}

void dump_spdm_auth_elevated_privilege_ended(const void *buffer, size_t buffer_size)
{
    printf("ELEVATED_PRIVILEGE_ENDED ");

    if (buffer_size < sizeof(spdm_auth_elevated_privilege_ended_response_t)) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
    }

    printf("\n");
}

void dump_spdm_auth_get_auth_capabilities(const void *buffer, size_t buffer_size)
{
    printf("GET_AUTH_CAPABILITIES ");

    if (buffer_size < sizeof(spdm_auth_get_auth_capabilities_request_t)) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
    }

    printf("\n");
}

void dump_spdm_auth_auth_capabilities(const void *buffer, size_t buffer_size)
{
    printf("AUTH_CAPABILITIES ");

    if (buffer_size < sizeof(spdm_auth_auth_capabilities_response_t)) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
    }

    printf("\n");
}

void dump_spdm_auth_auth_reset_to_default(const void *buffer, size_t buffer_size)
{
    printf("AUTH_RESET_TO_DEFAULT ");

    if (buffer_size < sizeof(spdm_auth_auth_reset_to_default_request_t)) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
    }

    printf("\n");
}

void dump_spdm_auth_auth_defaults_applied(const void *buffer, size_t buffer_size)
{
    printf("AUTH_DEFAULTS_APPLIED ");

    if (buffer_size < sizeof(spdm_auth_auth_defaults_applied_response_t)) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
    }

    printf("\n");
}

void dump_spdm_auth_take_ownership(const void *buffer, size_t buffer_size)
{
    printf("TAKE_OWNERSHIP ");

    if (buffer_size < sizeof(spdm_auth_take_ownership_request_t)) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
    }

    printf("\n");
}

void dump_spdm_auth_ownership_taken(const void *buffer, size_t buffer_size)
{
    printf("OWNERSHIP_TAKEN ");

    if (buffer_size < sizeof(spdm_auth_ownership_taken_response_t)) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
    }

    printf("\n");
}

void dump_spdm_auth_error(const void *buffer, size_t buffer_size)
{
    printf("ERROR ");

    if (buffer_size < sizeof(spdm_auth_error_response_t)) {
        printf("\n");
        return;
    }

    if (!m_param_quite_mode) {
        printf("() ");
    }

    printf("\n");
}

dispatch_table_entry_t m_spdm_auth_message_dispatch[] = {
    { SPDM_AUTH_GET_AUTH_VERSION, "GET_AUTH_VERSION", dump_spdm_auth_get_auth_version },
    { SPDM_AUTH_SELECT_AUTH_VERSION, "SELECT_AUTH_VERSION", dump_spdm_auth_select_auth_version },
    { SPDM_AUTH_SET_CRED_ID_PARAMS, "SET_CRED_ID_PARAMS", dump_spdm_auth_set_cred_id_params },
    { SPDM_AUTH_GET_CRED_ID_PARAMS, "GET_CRED_ID_PARAMS", dump_spdm_auth_get_cred_id_params },
    { SPDM_AUTH_SET_AUTH_POLICY, "SET_AUTH_POLICY", dump_spdm_auth_set_auth_policy },
    { SPDM_AUTH_GET_AUTH_POLICY, "GET_AUTH_POLICY", dump_spdm_auth_get_auth_policy },
    { SPDM_AUTH_START_AUTH, "START_AUTH", dump_spdm_auth_start_auth },
    { SPDM_AUTH_END_AUTH, "END_AUTH", dump_spdm_auth_end_auth },
    { SPDM_AUTH_ELEVATE_PRIVILEGE, "ELEVATE_PRIVILEGE", dump_spdm_auth_elevate_privilege },
    { SPDM_AUTH_END_ELEVATED_PRIVILEGE, "END_ELEVATED_PRIVILEGE", dump_spdm_auth_end_elevated_privilege },
    { SPDM_AUTH_GET_AUTH_CAPABILITIES, "GET_AUTH_CAPABILITIES", dump_spdm_auth_get_auth_capabilities },
    { SPDM_AUTH_AUTH_RESET_TO_DEFAULT, "AUTH_RESET_TO_DEFAULT", dump_spdm_auth_auth_reset_to_default },
    { SPDM_AUTH_TAKE_OWNERSHIP, "TAKE_OWNERSHIP", dump_spdm_auth_take_ownership },

    { SPDM_AUTH_AUTH_VERSION, "AUTH_VERSION", dump_spdm_auth_auth_version },
    { SPDM_AUTH_SELECT_AUTH_VERSION_RSP, "SELECT_AUTH_VERSION_RSP", dump_spdm_auth_select_auth_version_rsp },
    { SPDM_AUTH_SET_CRED_ID_PARAMS_DONE, "SET_CRED_ID_PARAMS_DONE", dump_spdm_auth_set_cred_id_params_done },
    { SPDM_AUTH_CRED_ID_PARAMS, "CRED_ID_PARAMS", dump_spdm_auth_cred_id_params },
    { SPDM_AUTH_SET_AUTH_POLICY_DONE, "SET_AUTH_POLICY_DONE", dump_spdm_auth_set_auth_policy_done },
    { SPDM_AUTH_AUTH_POLICY, "AUTH_POLICY", dump_spdm_auth_auth_policy },
    { SPDM_AUTH_START_AUTH_RSP, "START_AUTH_RSP", dump_spdm_auth_start_auth_rsp },
    { SPDM_AUTH_END_AUTH_RSP, "END_AUTH_RSP", dump_spdm_auth_end_auth_rsp },
    { SPDM_AUTH_PRIVILEGE_ELEVATED, "PRIVILEGE_ELEVATED", dump_spdm_auth_privilege_elevated },
    { SPDM_AUTH_ELEVATED_PRIVILEGE_ENDED, "ELEVATED_PRIVILEGE_ENDED", dump_spdm_auth_elevated_privilege_ended },
    { SPDM_AUTH_AUTH_CAPABILITIES, "AUTH_CAPABILITIES", dump_spdm_auth_auth_capabilities },
    { SPDM_AUTH_AUTH_DEFAULTS_APPLIED, "AUTH_DEFAULTS_APPLIED", dump_spdm_auth_auth_defaults_applied },
    { SPDM_AUTH_OWNERSHIP_TAKEN, "OWNERSHIP_TAKEN", dump_spdm_auth_ownership_taken },
    { SPDM_AUTH_ERROR, "ERROR", dump_spdm_auth_error },
};

void dump_spdm_auth_message(const void *buffer, size_t buffer_size)
{
    const spdm_auth_message_header_t *auth_header;

    if (buffer_size < sizeof(spdm_auth_message_header_t)) {
        printf("\n");
        return;
    }

    auth_header = buffer;
    printf("AUTH(%02x) ", auth_header->request_response_code);

    dump_dispatch_message(
        m_spdm_auth_message_dispatch,
        LIBSPDM_ARRAY_SIZE(m_spdm_auth_message_dispatch),
        auth_header->request_response_code,
        buffer,
        buffer_size);
}
