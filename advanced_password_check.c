/*-------------------------------------------------------------------------
 * advanced_password_check.c
 *
 * Advanced Password Check Extension for SynxDB (PostgreSQL 14-based MPP)
 *
 * 이전 패스워드 비교 방식:
 *   crypt.h의 get_role_password() + plain_crypt_verify() 활용
 *
 *   - get_role_password(): pg_authid에서 현재 저장된 해시값 조회
 *   - plain_crypt_verify(): 새 평문을 기존 해시의 salt/방식으로 해싱하여 비교
 *     → SCRAM-SHA-256이어도 동일한 패스워드인지 정확히 판별 가능
 *
 *   히스토리 테이블, dblink, SPI 불필요.
 *   직접 1개(현재 저장된 패스워드)와만 비교 가능.
 *   N개 히스토리가 필요하면 별도 히스토리 테이블 + Python 래퍼 병행 사용.
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include <ctype.h>
#include <string.h>

#include "fmgr.h"
#include "commands/user.h"        /* check_password_hook_type, check_password_hook */
#include "libpq/crypt.h"          /* PasswordType, get_role_password, plain_crypt_verify */
#include "utils/builtins.h"
#include "utils/guc.h"
#include "miscadmin.h"

PG_MODULE_MAGIC;

/* -------------------------------------------------------------------------
 * GUC Variables
 * ------------------------------------------------------------------------- */
static int  apc_min_length    = 9;
static int  apc_min_uppercase = 2;
static int  apc_min_lowercase = 2;
static int  apc_min_numbers   = 2;
static int  apc_min_special   = 2;
static bool apc_no_reuse      = true;  /* 현재 패스워드와 동일한 패스워드 재사용 방지 */

/* -------------------------------------------------------------------------
 * Hook storage
 * ------------------------------------------------------------------------- */
static check_password_hook_type prev_check_password_hook = NULL;

/* -------------------------------------------------------------------------
 * Forward declarations
 * ------------------------------------------------------------------------- */
void _PG_init(void);
void _PG_fini(void);

static void apc_check_password(const char *username, const char *shadow_pass,
                                PasswordType password_type, Datum validuntil_time,
                                bool validuntil_null);
static int  count_uppercase(const char *password);
static int  count_lowercase(const char *password);
static int  count_digits(const char *password);
static int  count_special(const char *password);
static bool is_special_char(char c);


/* -------------------------------------------------------------------------
 * _PG_init
 * ------------------------------------------------------------------------- */
void
_PG_init(void)
{
    DefineCustomIntVariable(
        "advanced_password_check.min_length",
        "Minimum number of characters required in a password.",
        NULL, &apc_min_length, 9, 1, 128, PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomIntVariable(
        "advanced_password_check.min_uppercase",
        "Minimum number of uppercase letters required in a password.",
        NULL, &apc_min_uppercase, 2, 0, 128, PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomIntVariable(
        "advanced_password_check.min_lowercase",
        "Minimum number of lowercase letters required in a password.",
        NULL, &apc_min_lowercase, 2, 0, 128, PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomIntVariable(
        "advanced_password_check.min_numbers",
        "Minimum number of digit characters required in a password.",
        NULL, &apc_min_numbers, 2, 0, 128, PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomIntVariable(
        "advanced_password_check.min_special",
        "Minimum number of special characters required in a password.",
        NULL, &apc_min_special, 2, 0, 128, PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomBoolVariable(
        "advanced_password_check.no_reuse",
        "Prevent reuse of the current password.",
        "When enabled, the new password must differ from the currently stored password.",
        &apc_no_reuse, true, PGC_SUSET, 0, NULL, NULL, NULL);

    prev_check_password_hook = check_password_hook;
    check_password_hook = apc_check_password;

    ereport(LOG, (errmsg("advanced_password_check: extension loaded successfully")));
}

/* -------------------------------------------------------------------------
 * _PG_fini
 * ------------------------------------------------------------------------- */
void
_PG_fini(void)
{
    check_password_hook = prev_check_password_hook;
}

/* -------------------------------------------------------------------------
 * 문자 분류 헬퍼
 * ------------------------------------------------------------------------- */
static bool
is_special_char(char c)
{
    return (!isalnum((unsigned char) c) && isprint((unsigned char) c));
}

static int
count_uppercase(const char *password)
{
    int count = 0;
    for (const char *p = password; *p; p++)
        if (isupper((unsigned char) *p)) count++;
    return count;
}

static int
count_lowercase(const char *password)
{
    int count = 0;
    for (const char *p = password; *p; p++)
        if (islower((unsigned char) *p)) count++;
    return count;
}

static int
count_digits(const char *password)
{
    int count = 0;
    for (const char *p = password; *p; p++)
        if (isdigit((unsigned char) *p)) count++;
    return count;
}

static int
count_special(const char *password)
{
    int count = 0;
    for (const char *p = password; *p; p++)
        if (is_special_char(*p)) count++;
    return count;
}


/* -------------------------------------------------------------------------
 * apc_check_password  -  메인 훅 함수
 *
 * shadow_pass: 사용자가 입력한 새 패스워드 (평문)
 * -------------------------------------------------------------------------
 */
static void
apc_check_password(const char *username,
                   const char *shadow_pass,
                   PasswordType password_type,
                   Datum validuntil_time,
                   bool validuntil_null)
{
    /* 이전 훅 체이닝 */
    if (prev_check_password_hook)
        (*prev_check_password_hook)(username, shadow_pass, password_type,
                                    validuntil_time, validuntil_null);

    /* 평문이 아니면 검사 불가 */
    if (password_type != PASSWORD_TYPE_PLAINTEXT)
    {
        ereport(NOTICE,
                (errmsg("advanced_password_check: password policy cannot be "
                        "enforced on pre-hashed passwords")));
        return;
    }

    int pass_len  = (int) strlen(shadow_pass);
    int n_upper   = count_uppercase(shadow_pass);
    int n_lower   = count_lowercase(shadow_pass);
    int n_digits  = count_digits(shadow_pass);
    int n_special = count_special(shadow_pass);

    /* ---- 1. 최소 길이 ---- */
    if (pass_len < apc_min_length)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("password is too short"),
                 errdetail("Password must be at least %d characters long. "
                           "Current length: %d.",
                           apc_min_length, pass_len)));

    /* ---- 2. 대문자 ---- */
    if (n_upper < apc_min_uppercase)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("password does not contain enough uppercase letters"),
                 errdetail("Password must contain at least %d uppercase letter(s). "
                           "Found: %d.",
                           apc_min_uppercase, n_upper)));

    /* ---- 3. 소문자 ---- */
    if (n_lower < apc_min_lowercase)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("password does not contain enough lowercase letters"),
                 errdetail("Password must contain at least %d lowercase letter(s). "
                           "Found: %d.",
                           apc_min_lowercase, n_lower)));

    /* ---- 4. 숫자 ---- */
    if (n_digits < apc_min_numbers)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("password does not contain enough digit characters"),
                 errdetail("Password must contain at least %d digit(s). "
                           "Found: %d.",
                           apc_min_numbers, n_digits)));

    /* ---- 5. 특수문자 ---- */
    if (n_special < apc_min_special)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("password does not contain enough special characters"),
                 errdetail("Password must contain at least %d special character(s) "
                           "(e.g. !@#$%%^&*). Found: %d.",
                           apc_min_special, n_special)));

    /* ---- 6. 현재 패스워드와 동일 여부 ---- */
    if (apc_no_reuse)
    {
        char *logdetail  = NULL;
        char *current_shadow = get_role_password(username, &logdetail);

        if (current_shadow != NULL)
        {
            /*
             * plain_crypt_verify:
             *   role         = 유저명
             *   shadow_pass  = pg_authid에 저장된 현재 해시값
             *                  (SCRAM-SHA-256 또는 MD5)
             *   client_pass  = 새로 입력한 평문
             *   logdetail    = 에러 상세 메시지 (불필요 시 NULL)
             *
             * 반환값:
             *   STATUS_OK (0)    = 새 평문이 현재 저장된 패스워드와 동일
             *   STATUS_ERROR(-1) = 다름
             *
             * SCRAM의 경우 내부적으로:
             *   저장된 salt + 반복횟수로 새 평문을 동일하게 해싱 후 비교
             *   → 평문을 복원하지 않고도 동일 여부 정확히 판별 가능
             */
            int verify_result = plain_crypt_verify(username,
                                                   current_shadow,
                                                   shadow_pass,
                                                   &logdetail);
            pfree(current_shadow);

            if (verify_result == STATUS_OK)
                ereport(ERROR,
                        (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                         errmsg("new password must differ from the current password"),
                         errdetail("The new password is identical to the currently "
                                   "stored password. Please choose a different password.")));
        }
        /* 기존 패스워드 없으면 (신규 유저) 스킵 */
    }

    ereport(DEBUG1,
            (errmsg("advanced_password_check: password passed all policy checks "
                    "for user \"%s\"", username)));
}
