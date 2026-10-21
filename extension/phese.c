/* SPDX-License-Identifier: MIT */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "php.h"
#include "ext/standard/info.h"
#include "SAPI.h"
#include "main/php_output.h"
#include "phese_seccomp.h"
#include <string.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <syslog.h>
#include <time.h>
#ifdef ZTS
#include <pthread.h>
#endif

#define PHP_PHESE_VERSION "1.0.0"

static int phese_filter_installed = 0;
static int phese_worker_scope = 0;
static int phese_worker_failed = 0;
#ifdef ZTS
/* The FPM/Apache parent never enters worker RINIT, so supervisor forks inherit
 * an unlocked mutex. A completed process-wide filter is read with acquire
 * semantics before taking the mutex on any later request. */
static pthread_mutex_t phese_worker_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif
static void (*phese_previous_execute_internal)(zend_execute_data *, zval *) = NULL;
static char *phese_block_page = NULL;
static char *phese_csp_header = NULL;
static _Thread_local int phese_blocking = 0;
static _Thread_local int phese_request_active = 0;
static _Thread_local zval phese_deferred_header_callback;
static pid_t phese_seen_worker = 0;
static unsigned long long phese_event_counter = 0;

PHP_INI_BEGIN()
    PHP_INI_ENTRY("phese.scope", "startup", PHP_INI_SYSTEM, NULL)
    PHP_INI_ENTRY("phese.block_page", "", PHP_INI_SYSTEM, NULL)
    PHP_INI_ENTRY("phese.block_csp", "default-src 'none'; img-src https://i.ibb.co; frame-src https://www.youtube-nocookie.com; style-src 'unsafe-inline'; script-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'", PHP_INI_SYSTEM, NULL)
PHP_INI_END()

static const char phese_fallback_page[] =
    "<!doctype html><html lang=\"ko\"><meta charset=\"utf-8\">"
    "<title>접근 차단</title><h1>입원 처리되었습니다</h1>"
    "<p>공격 위험성이 감지되어 폐쇄적 환경의 안정실로 요청을 격리했습니다.</p>"
    "<p>참조: {{EVENT_ID}}</p><p>시각: {{TIMESTAMP}}</p></html>";

/* Fixed schema and whitelist-only inputs. Never include arguments, paths or bodies. */
static void phese_audit(const char *event, const char *reason, const char *function,
                        char event_id[33], char timestamp[40])
{
    struct timespec now = {0};
    struct tm utc;
    unsigned char random_bytes[16];
    char json[1400], message[1600], date[24];
    unsigned long long sequence = __atomic_add_fetch(&phese_event_counter, 1, __ATOMIC_RELAXED);
    (void)clock_gettime(CLOCK_REALTIME, &now);
    if (gmtime_r(&now.tv_sec, &utc) == NULL) memset(&utc, 0, sizeof(utc));
    strftime(date, sizeof(date), "%Y-%m-%dT%H:%M:%S", &utc);
    snprintf(timestamp, 40, "%s.%09ldZ", date, now.tv_nsec);
    if (getrandom(random_bytes, sizeof(random_bytes), GRND_NONBLOCK) == (ssize_t)sizeof(random_bytes)) {
        for (size_t i = 0; i < sizeof(random_bytes); ++i)
            snprintf(event_id + 2 * i, 3, "%02x", random_bytes[i]);
    } else {
        snprintf(event_id, 33, "%08x%08x%016llx", (unsigned int)getpid(),
                 (unsigned int)now.tv_sec, sequence ^ (unsigned long long)now.tv_nsec);
    }
    snprintf(json, sizeof(json),
        "{\"product\":\"AsylumEnforce\",\"component\":\"phese\","
        "\"event\":\"%s\",\"event_id\":\"%s\",\"timestamp\":\"%s\","
        "\"pid\":%ld,\"reason\":\"%s\",\"function\":\"%s\","
        "\"terminology\":{\"isolation\":\"입원\",\"sandbox\":\"폐쇄적 환경\","
        "\"deep_isolation\":\"안정실\",\"risk\":\"공격 위험성\"},"
        "\"message\":\"ㅋㅋㅋㅋㅋ어떻게병동이름이폐쇄얔ㅋㅋㅋㅋㅋㅋ\"}",
        event, event_id, timestamp, (long)getpid(), reason, function ? function : "startup");
    static const char *const months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    char syslog_date[32];
    unsigned int month = utc.tm_mon >= 0 && utc.tm_mon < 12 ? (unsigned int)utc.tm_mon : 0;
    snprintf(syslog_date, sizeof(syslog_date), "%s %2d %02d:%02d:%02d",
             months[month], utc.tm_mday, utc.tm_hour, utc.tm_min, utc.tm_sec);
    int length = snprintf(message, sizeof(message), "<%d>%s phese[%ld]: %s",
                          LOG_AUTHPRIV | (strcmp(event, "sandbox_started") == 0 ? LOG_NOTICE : LOG_WARNING),
                          syslog_date, (long)getpid(), json);
    if (length <= 0 || (size_t)length >= sizeof(message)) return;
    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) return;
    struct sockaddr_un destination = {0};
    destination.sun_family = AF_UNIX;
    memcpy(destination.sun_path, "/dev/log", sizeof("/dev/log"));
    (void)sendto(fd, message, (size_t)length, MSG_DONTWAIT | MSG_NOSIGNAL,
                 (struct sockaddr *)&destination, sizeof(destination));
    close(fd);
}

static int phese_load_block_page(void)
{
    const char *csp = INI_STR("phese.block_csp");
    if (!csp || !*csp || strlen(csp) > 4096 || strchr(csp, '\r') || strchr(csp, '\n')) return -1;
    size_t csp_length = strlen(csp) + sizeof("Content-Security-Policy: ");
    phese_csp_header = malloc(csp_length);
    if (!phese_csp_header) return -1;
    snprintf(phese_csp_header, csp_length, "Content-Security-Policy: %s", csp);
    const char *path = INI_STR("phese.block_page");
    if (!path || !*path) return 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    struct stat metadata;
    if (fstat(fd, &metadata) || !S_ISREG(metadata.st_mode) || metadata.st_uid != 0 ||
        (metadata.st_mode & (S_IWGRP | S_IWOTH)) || metadata.st_size <= 0 ||
        metadata.st_size > 262144) { close(fd); return -1; }
    size_t length = (size_t)metadata.st_size;
    char *page = malloc(length + 1);
    if (!page) { close(fd); return -1; }
    size_t offset = 0;
    while (offset < length) {
        ssize_t count = read(fd, page + offset, length - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { free(page); close(fd); return -1; }
        offset += (size_t)count;
    }
    close(fd);
    if (memchr(page, '\0', length)) { free(page); return -1; }
    page[length] = '\0';
    phese_block_page = page;
    return 0;
}

static void phese_direct_write(const char *data, size_t length)
{
    while (length > 0) {
        size_t written = sapi_module.ub_write(data, length);
        if (!written || written > length) break;
        data += written;
        length -= written;
    }
}

static void phese_render_block_page(const char *event_id, const char *timestamp)
{
    const char *cursor = phese_block_page ? phese_block_page : phese_fallback_page;
    while (*cursor) {
        const char *id = strstr(cursor, "{{EVENT_ID}}");
        const char *time = strstr(cursor, "{{TIMESTAMP}}");
        const char *next = id && (!time || id < time) ? id : time;
        if (!next) { phese_direct_write(cursor, strlen(cursor)); break; }
        phese_direct_write(cursor, (size_t)(next - cursor));
        if (next == id) {
            phese_direct_write(event_id, strlen(event_id));
            cursor = next + sizeof("{{EVENT_ID}}") - 1;
        } else {
            phese_direct_write(timestamp, strlen(timestamp));
            cursor = next + sizeof("{{TIMESTAMP}}") - 1;
        }
    }
}

static void phese_execute_internal(zend_execute_data *execute_data, zval *return_value)
{
    static const char *const blocked[] = {
        "exec", "system", "shell_exec", "passthru", "proc_open", "popen",
        "pcntl_exec", "mail", "mb_send_mail", "dl", NULL
    };
    const char *function = NULL;
    const char *reason = "process_execution_attempt";
    zend_string *name = execute_data->func->common.function_name;
    zend_class_entry *scope = execute_data->func->common.scope;
    if (scope && zend_string_equals_literal_ci(scope->name, "FFI")) {
        function = "FFI";
        reason = "native_interface_attempt";
    } else if (!scope && name) {
        for (size_t i = 0; blocked[i]; ++i) {
            if (zend_string_equals_cstr(name, blocked[i], strlen(blocked[i]))) {
                function = blocked[i];
                if (strcmp(function, "dl") == 0) reason = "native_interface_attempt";
                break;
            }
        }
    }
    if (function) {
        char event_id[33], timestamp[40];
        phese_audit("policy_denied", reason, function, event_id, timestamp);
        int is_cli = strcmp(sapi_module.name, "cli") == 0 || strcmp(sapi_module.name, "phpdbg") == 0;
        if (!is_cli && phese_request_active && SG(server_context) != NULL) {
            if (phese_blocking) zend_bailout();
            phese_blocking = 1;
            /* Bypass user output callbacks and suppress later buffered app output. */
            php_output_set_status(PHP_OUTPUT_DISABLED);
            if (Z_TYPE(SG(callback_func)) != IS_UNDEF) {
                ZVAL_COPY_VALUE(&phese_deferred_header_callback, &SG(callback_func));
                ZVAL_UNDEF(&SG(callback_func));
            }
            if (!SG(headers_sent)) {
                sapi_header_line type = {0}, cache = {0}, csp = {0}, nosniff = {0}, referrer = {0};
                static const char *const stale_headers[] = {"Content-Length", "Content-Encoding", "Location", "Status", NULL};
                for (size_t i = 0; stale_headers[i]; ++i) {
                    sapi_header_line stale = {0};
                    stale.line = (char *)stale_headers[i];
                    stale.line_len = strlen(stale.line);
                    (void)sapi_header_op(SAPI_HEADER_DELETE, &stale);
                }
                type.line = "Content-Type: text/html; charset=UTF-8";
                type.line_len = strlen(type.line);
                cache.line = "Cache-Control: no-store";
                cache.line_len = strlen(cache.line);
                (void)sapi_header_op(SAPI_HEADER_REPLACE, &type);
                (void)sapi_header_op(SAPI_HEADER_REPLACE, &cache);
                csp.line = phese_csp_header;
                csp.line_len = strlen(csp.line);
                (void)sapi_header_op(SAPI_HEADER_REPLACE, &csp);
                nosniff.line = "X-Content-Type-Options: nosniff";
                nosniff.line_len = strlen(nosniff.line);
                (void)sapi_header_op(SAPI_HEADER_REPLACE, &nosniff);
                referrer.line = "Referrer-Policy: no-referrer";
                referrer.line_len = strlen(referrer.line);
                (void)sapi_header_op(SAPI_HEADER_REPLACE, &referrer);
                (void)sapi_header_op(SAPI_HEADER_SET_STATUS, (void *)(intptr_t)403);
                if (SG(sapi_headers).http_status_line) {
                    efree(SG(sapi_headers).http_status_line);
                    SG(sapi_headers).http_status_line = NULL;
                }
            }
            (void)sapi_send_headers();
            phese_render_block_page(event_id, timestamp);
            sapi_flush();
            zend_bailout();
        }
        /* CLI audit observes an attempt. seccomp enforces exec; FFI/dl may succeed. */
    }
    if (phese_previous_execute_internal) phese_previous_execute_internal(execute_data, return_value);
    else execute_data->func->internal_function.handler(execute_data, return_value);
}

static int phese_supported_version(zend_long version)
{
    if (version >= 80235 && version < 80300) return 1;
    if (version >= 80336 && version < 80400) return 1;
    if (version >= 80427 && version < 80500) return 1;
    if (version >= 80512 && version < 80600) return 1;
    return 0;
}

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_phese_status, 0, 0, IS_ARRAY, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(phese_status)
{
    ZEND_PARSE_PARAMETERS_NONE();
    array_init(return_value);
    add_assoc_string(return_value, "version", PHP_PHESE_VERSION);
    add_assoc_string(return_value, "name", "phese (폐쇄!)");
    add_assoc_string(return_value, "scope", phese_worker_scope ? "worker" : "startup");
    add_assoc_bool(return_value, "enforcing",
                   __atomic_load_n(&phese_filter_installed, __ATOMIC_ACQUIRE) == 1 &&
                   __atomic_load_n(&phese_worker_failed, __ATOMIC_ACQUIRE) == 0);
    add_assoc_bool(return_value, "no_new_privileges",
                   prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1);
    add_assoc_bool(return_value, "seccomp_active",
                   prctl(PR_GET_SECCOMP, 0, 0, 0, 0) == SECCOMP_MODE_FILTER);
    add_assoc_bool(return_value, "version_gate", 1);
    add_assoc_long(return_value, "effective_uid", (zend_long)geteuid());
    add_assoc_long(return_value, "effective_gid", (zend_long)getegid());
    add_assoc_bool(return_value, "process_exec_allowed", 0);
    add_assoc_bool(return_value, "network_isolated", 0);
    add_assoc_bool(return_value, "filesystem_isolated", 0);
}

static const zend_function_entry phese_functions[] = {
    PHP_FE(phese_status, arginfo_phese_status)
    PHP_FE_END
};

static int phese_enforce_current_process(void)
{
    if (phese_install_filter() != 0) {
        int saved_errno = errno;
        char event_id[33], timestamp[40];
        phese_audit("policy_denied", "mandatory_seccomp_unavailable", NULL, event_id, timestamp);
        php_error_docref(NULL, E_WARNING,
            "phese cannot install mandatory seccomp/no_new_privs: %s; "
            "refusing request processing", strerror(saved_errno));
        return FAILURE;
    }
    __atomic_store_n(&phese_filter_installed, 1, __ATOMIC_RELEASE);
    char event_id[33], timestamp[40];
    phese_audit("sandbox_started", "seccomp_installed", NULL, event_id, timestamp);
    return SUCCESS;
}

static int phese_enforce_worker_once(void)
{
    int result = SUCCESS, saved_errno = 0, installed_here = 0;
    if (__atomic_load_n(&phese_worker_failed, __ATOMIC_ACQUIRE)) goto failed;
    if (__atomic_load_n(&phese_filter_installed, __ATOMIC_ACQUIRE) == 1) return SUCCESS;
#ifdef ZTS
    int lock_result = pthread_mutex_lock(&phese_worker_mutex);
    if (lock_result != 0) {
        saved_errno = lock_result;
        __atomic_store_n(&phese_worker_failed, 1, __ATOMIC_RELEASE);
        goto failed;
    }
#endif
    /* No PHP diagnostics or callbacks may run while the mutex is held: a Zend
     * bailout would otherwise leave every waiting request locked forever. */
    if (__atomic_load_n(&phese_worker_failed, __ATOMIC_ACQUIRE)) {
        result = FAILURE;
    } else if (__atomic_load_n(&phese_filter_installed, __ATOMIC_ACQUIRE) == 0) {
        if (phese_install_filter() != 0) {
            saved_errno = errno;
            __atomic_store_n(&phese_worker_failed, 1, __ATOMIC_RELEASE);
            result = FAILURE;
        } else {
            __atomic_store_n(&phese_filter_installed, 1, __ATOMIC_RELEASE);
            installed_here = 1;
        }
    }
#ifdef ZTS
    int unlock_result = pthread_mutex_unlock(&phese_worker_mutex);
    if (unlock_result != 0) {
        saved_errno = unlock_result;
        __atomic_store_n(&phese_worker_failed, 1, __ATOMIC_RELEASE);
        result = FAILURE;
    }
#endif
    if (result == FAILURE) goto failed;
    if (installed_here) {
        char event_id[33], timestamp[40];
        phese_audit("sandbox_started", "seccomp_installed", NULL, event_id, timestamp);
    }
    return SUCCESS;
failed:
    {
        char event_id[33], timestamp[40];
        phese_audit("policy_denied", "mandatory_seccomp_unavailable", NULL, event_id, timestamp);
        php_error_docref(NULL, E_WARNING,
            "phese cannot install mandatory seccomp/no_new_privs: %s; refusing request processing",
            saved_errno ? strerror(saved_errno) : "worker enforcement previously failed");
    }
    return FAILURE;
}

PHP_MINIT_FUNCTION(phese)
{
    REGISTER_INI_ENTRIES();
    zval *runtime_version = zend_get_constant_str(ZEND_STRL("PHP_VERSION_ID"));
    zval *extra_version = zend_get_constant_str(ZEND_STRL("PHP_EXTRA_VERSION"));
    if (!extra_version || Z_TYPE_P(extra_version) != IS_STRING ||
        Z_STRLEN_P(extra_version) != 0 || !runtime_version || Z_TYPE_P(runtime_version) != IS_LONG ||
        !phese_supported_version(Z_LVAL_P(runtime_version))) {
        char event_id[33], timestamp[40];
        phese_audit("version_refused", "unpatched_or_unsupported_php", NULL, event_id, timestamp);
        php_error_docref(NULL, E_WARNING,
            "phese refuses this runtime: require stable PHP 8.2.35+, 8.3.36+, "
            "8.4.27+ or 8.5.12+ in the corresponding supported branch; "
            "update PHP before enabling request processing");
        return FAILURE;
    }
    const char *scope = INI_STR("phese.scope");
    if (!scope || (strcmp(scope, "startup") != 0 && strcmp(scope, "worker") != 0)) {
        php_error_docref(NULL, E_WARNING, "phese.scope must be startup or worker");
        return FAILURE;
    }
    phese_worker_scope = strcmp(scope, "worker") == 0;
    int is_fpm = strcmp(sapi_module.name, "fpm-fcgi") == 0;
    int is_apache = strcmp(sapi_module.name, "apache2handler") == 0;
    if (phese_worker_scope && !is_fpm && !is_apache) {
        php_error_docref(NULL, E_WARNING, "phese.scope=worker is allowed only for PHP-FPM or Apache");
        return FAILURE;
    }
    if (is_apache && !phese_worker_scope) {
        php_error_docref(NULL, E_WARNING,
            "phese.scope=startup is not supported for Apache; set phese.scope=worker "
            "to preserve the graceful reload lifecycle");
        return FAILURE;
    }
    if (phese_load_block_page() != 0) {
        php_error_docref(NULL, E_WARNING, "phese block page/CSP configuration failed validation");
        return FAILURE;
    }
    if (!phese_worker_scope && phese_enforce_current_process() == FAILURE) {
        return FAILURE;
    }
    phese_previous_execute_internal = zend_execute_internal;
    zend_execute_internal = phese_execute_internal;
    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(phese)
{
    if (zend_execute_internal == phese_execute_internal)
        zend_execute_internal = phese_previous_execute_internal;
    free(phese_block_page);
    phese_block_page = NULL;
    free(phese_csp_header);
    phese_csp_header = NULL;
    UNREGISTER_INI_ENTRIES();
    return SUCCESS;
}

PHP_RINIT_FUNCTION(phese)
{
#if defined(ZTS) && defined(COMPILE_DL_PHESE)
    ZEND_TSRMLS_CACHE_UPDATE();
#endif
    phese_blocking = 0;
    phese_request_active = 0;
    ZVAL_UNDEF(&phese_deferred_header_callback);
    /* Version/info commands and preload are not accepted HTTP requests. The
     * parent keeps its original syscall state for fork and graceful reload. */
    if (phese_worker_scope) {
        if (SG(server_context) == NULL || SG(request_info).request_method == NULL) return SUCCESS;
        if (geteuid() == 0) {
            char event_id[33], timestamp[40];
            phese_audit("policy_denied", "worker_privilege_drop_required", NULL, event_id, timestamp);
            php_error_docref(NULL, E_WARNING,
                "phese worker enforcement requires a non-root pool UID or Apache worker UID");
            return FAILURE;
        }
        if (phese_enforce_worker_once() == FAILURE) return FAILURE;
    }
    phese_request_active = 1;
    pid_t current = getpid();
    pid_t observed = __atomic_load_n(&phese_seen_worker, __ATOMIC_RELAXED);
    if (observed != current && __atomic_compare_exchange_n(&phese_seen_worker,
        &observed, current, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
        char event_id[33], timestamp[40];
        phese_audit("sandbox_started", "policy_enforced", NULL, event_id, timestamp);
    }
    return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(phese)
{
    if (Z_TYPE(phese_deferred_header_callback) != IS_UNDEF) {
        zval callback;
        ZVAL_COPY_VALUE(&callback, &phese_deferred_header_callback);
        ZVAL_UNDEF(&phese_deferred_header_callback);
        /* Object destructors may bail out; the admission response is already sent. */
        zend_try { zval_ptr_dtor(&callback); } zend_catch { } zend_end_try();
    }
    phese_request_active = 0;
    return SUCCESS;
}

PHP_MINFO_FUNCTION(phese)
{
    php_info_print_table_start();
    php_info_print_table_header(2, "phese (폐쇄!)", "enabled");
    php_info_print_table_row(2, "Scope", phese_worker_scope ? "worker" : "startup");
    php_info_print_table_row(2, "Kernel filter",
        __atomic_load_n(&phese_filter_installed, __ATOMIC_ACQUIRE) == 1 ? "installed" : "pending worker request");
    php_info_print_table_row(2, "Version", PHP_PHESE_VERSION);
    php_info_print_table_row(2, "Process execution", "denied by seccomp");
    php_info_print_table_row(2, "Filesystem/network isolation", "requires outer sandbox");
    php_info_print_table_end();
}

zend_module_entry phese_module_entry = {
    STANDARD_MODULE_HEADER,
    "phese",
    phese_functions,
    PHP_MINIT(phese),
    PHP_MSHUTDOWN(phese),
    PHP_RINIT(phese),
    PHP_RSHUTDOWN(phese),
    PHP_MINFO(phese),
    PHP_PHESE_VERSION,
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_PHESE
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
#endif
ZEND_GET_MODULE(phese)
#endif
