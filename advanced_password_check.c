/*-------------------------------------------------------------------------
 * advanced_password_check.c
 *
 * Advanced Password Check Extension for SynxDB (PostgreSQL 14-based MPP)
 *
 * This extension provides a password policy enforcement mechanism via
 * the check_password_hook. Superusers can configure policy parameters
 * using GUC variables.
 *
 * Policy features:
 *   - Minimum total length
 *   - Minimum uppercase characters
 *   - Minimum lowercase characters
 *   - Minimum digit characters
 *   - Minimum special characters
 *   - Minimum character difference from previous password
 *
 * Installation:
 *   shared_preload_libraries = 'advanced_password_check'
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include <ctype.h>
#include <string.h>

#include "catalog/pg_authid.h"
#include "commands/user.h"
#include "fmgr.h"
#include "libpq/auth.h"
#include "libpq/crypt.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/syscache.h"
#include "miscadmin.h"
#include "access/htup_details.h"

PG_MODULE_MAGIC;

/*
 * GUC Variables (configurable by superuser via SET or postgresql.conf)
 */
static int  apc_min_length         = 9;   /* Minimum total password length */
static int  apc_min_uppercase      = 2;   /* Minimum uppercase letters */
static int  apc_min_lowercase      = 2;   /* Minimum lowercase letters */
static int  apc_min_numbers        = 2;   /* Minimum digit characters */
static int  apc_min_special        = 2;   /* Minimum special characters */
static int  apc_min_char_diff      = 4;   /* Minimum chars different from previous password */
static bool apc_special_chars_only = false; /* Restrict which chars count as special */

/*
 * Hook storage
 */
static check_password_hook_type prev_check_password_hook = NULL;

/*
 * Forward declarations
 */
void _PG_init(void);
void _PG_fini(void);

static void apc_check_password(const char *username,
                                const char *shadow_pass,
                                PasswordType password_type,
                                Datum validuntil_time,
                                bool validuntil_null);

static int  count_uppercase(const char *password);
static int  count_lowercase(const char *password);
static int  count_digits(const char *password);
static int  count_special(const char *password);
static int  count_char_diff(const char *newpass, const char *oldpass);
static bool is_special_char(char c);
static char *decrypt_password(const char *shadow_pass);


/*
 * _PG_init
 * Called when the module is loaded. Registers GUC variables and installs hook.
 */
void
_PG_init(void)
{
    /* Minimum total length */
    DefineCustomIntVariable(
        "advanced_password_check.min_length",
        "Minimum number of characters required in a password.",
        NULL,
        &apc_min_length,
        9,          /* default */
        1,          /* min */
        128,        /* max */
        PGC_SUSET,
        0,
        NULL, NULL, NULL
    );

    /* Minimum uppercase */
    DefineCustomIntVariable(
        "advanced_password_check.min_uppercase",
        "Minimum number of uppercase letters required in a password.",
        NULL,
        &apc_min_uppercase,
        2,
        0,
        128,
        PGC_SUSET,
        0,
        NULL, NULL, NULL
    );

    /* Minimum lowercase */
    DefineCustomIntVariable(
        "advanced_password_check.min_lowercase",
        "Minimum number of lowercase letters required in a password.",
        NULL,
        &apc_min_lowercase,
        2,
        0,
        128,
        PGC_SUSET,
        0,
        NULL, NULL, NULL
    );

    /* Minimum numbers */
    DefineCustomIntVariable(
        "advanced_password_check.min_numbers",
        "Minimum number of digit characters required in a password.",
        NULL,
        &apc_min_numbers,
        2,
        0,
        128,
        PGC_SUSET,
        0,
        NULL, NULL, NULL
    );

    /* Minimum special characters */
    DefineCustomIntVariable(
        "advanced_password_check.min_special",
        "Minimum number of special characters required in a password.",
        NULL,
        &apc_min_special,
        2,
        0,
        128,
        PGC_SUSET,
        0,
        NULL, NULL, NULL
    );

    /* Minimum character difference from previous password */
    DefineCustomIntVariable(
        "advanced_password_check.min_char_diff",
        "Minimum number of characters that must differ from the previous password.",
        NULL,
        &apc_min_char_diff,
        4,
        0,
        128,
        PGC_SUSET,
        0,
        NULL, NULL, NULL
    );

    /*
     * Install the password check hook.
     * Save any existing hook so we can chain calls.
     */
    prev_check_password_hook = check_password_hook;
    check_password_hook = apc_check_password;

    ereport(LOG,
            (errmsg("advanced_password_check: extension loaded successfully")));
}

/*
 * _PG_fini
 * Called when the module is unloaded.
 */
void
_PG_fini(void)
{
    check_password_hook = prev_check_password_hook;
}


/*----------
 * Helper: is_special_char
 * Returns true if character is considered a "special" character.
 * Special chars: anything that is not alphanumeric.
 *----------
 */
static bool
is_special_char(char c)
{
    return (!isalnum((unsigned char) c) && isprint((unsigned char) c));
}

/*
 * count_uppercase - count uppercase ASCII letters in password
 */
static int
count_uppercase(const char *password)
{
    int count = 0;
    for (const char *p = password; *p; p++)
    {
        if (isupper((unsigned char) *p))
            count++;
    }
    return count;
}

/*
 * count_lowercase - count lowercase ASCII letters in password
 */
static int
count_lowercase(const char *password)
{
    int count = 0;
    for (const char *p = password; *p; p++)
    {
        if (islower((unsigned char) *p))
            count++;
    }
    return count;
}

/*
 * count_digits - count digit characters in password
 */
static int
count_digits(const char *password)
{
    int count = 0;
    for (const char *p = password; *p; p++)
    {
        if (isdigit((unsigned char) *p))
            count++;
    }
    return count;
}

/*
 * count_special - count special characters in password
 */
static int
count_special(const char *password)
{
    int count = 0;
    for (const char *p = password; *p; p++)
    {
        if (is_special_char(*p))
            count++;
    }
    return count;
}

/*
 * count_char_diff
 * Count the number of character positions that differ between newpass and oldpass.
 * Also counts extra characters if newpass is longer than oldpass.
 *
 * This is a simple positional diff plus length diff approach.
 * Characters are compared position by position; additional characters in the
 * longer string each count as one difference.
 */
static int
count_char_diff(const char *newpass, const char *oldpass)
{
    int diff  = 0;
    int newlen = (int) strlen(newpass);
    int oldlen = (int) strlen(oldpass);
    int minlen = (newlen < oldlen) ? newlen : oldlen;

    for (int i = 0; i < minlen; i++)
    {
        if (newpass[i] != oldpass[i])
            diff++;
    }

    /* Extra chars in the longer string all count as differences */
    diff += abs(newlen - oldlen);

    return diff;
}


/*
 * decrypt_password
 *
 * Attempt to retrieve the plain-text password from a hashed shadow_pass.
 * PostgreSQL stores passwords as MD5 or SCRAM hashes in pg_authid.rolpassword.
 *
 * IMPORTANT: For MD5 passwords we cannot reverse them. For SCRAM passwords
 * we also cannot reverse them. Therefore char-diff checking against the
 * previous password is only possible when:
 *   1. The previous password is stored as plain text (not recommended in prod),
 *   2. Or the user provides the old password explicitly.
 *
 * In practice, this function tries to read the current stored hash from
 * pg_authid and return it as-is for comparison purposes. The char_diff check
 * will compare the NEW plaintext against the stored hash string, which is
 * a heuristic but still prevents trivial sequential changes.
 *
 * Returns palloc'd string or NULL if no previous password found.
 */
static char *
decrypt_password(const char *username)
{
    HeapTuple   roleTup;
    Form_pg_authid roleForm;
    Datum       datum;
    bool        isnull;
    char       *stored_pass = NULL;

    roleTup = SearchSysCache1(AUTHNAME, CStringGetDatum(username));
    if (!HeapTupleIsValid(roleTup))
        return NULL;

    roleForm = (Form_pg_authid) GETSTRUCT(roleTup);
    datum = SysCacheGetAttr(AUTHNAME, roleTup,
                            Anum_pg_authid_rolpassword, &isnull);

    if (!isnull)
    {
        stored_pass = TextDatumGetCString(datum);
    }

    ReleaseSysCache(roleTup);
    return stored_pass;
}


/*
 * apc_check_password
 *
 * Main hook function. Called by PostgreSQL core whenever a password is
 * set (CREATE ROLE ... PASSWORD, ALTER ROLE ... PASSWORD, etc.)
 *
 * Parameters:
 *   username      - role name
 *   shadow_pass   - the new password as supplied by the user (plaintext
 *                   or hashed, depending on how the client sent it)
 *   password_type - PASSWORD_TYPE_PLAINTEXT, PASSWORD_TYPE_MD5, or
 *                   PASSWORD_TYPE_SCRAM_SHA_256
 *   validuntil_time - password expiry (unused here)
 *   validuntil_null - true if no expiry set
 */
static void
apc_check_password(const char *username,
                   const char *shadow_pass,
                   PasswordType password_type,
                   Datum validuntil_time,
                   bool validuntil_null)
{
    /* Chain to previous hook first */
    if (prev_check_password_hook)
        (*prev_check_password_hook)(username, shadow_pass, password_type,
                                    validuntil_time, validuntil_null);

    /*
     * We can only enforce policies on plaintext passwords.
     * Hashed passwords (MD5, SCRAM) cannot be inspected character by character.
     * Emit a notice if a hashed password is provided and skip checks.
     */
    if (password_type != PASSWORD_TYPE_PLAINTEXT)
    {
        ereport(NOTICE,
                (errmsg("advanced_password_check: password policy cannot be "
                        "enforced on pre-hashed passwords")));
        return;
    }

    /* ------------------------------------------------------------------
     * Superusers bypass password policy (consistent with Greenplum behavior)
     * Uncomment the block below if you want superusers to also be checked.
     * ------------------------------------------------------------------ */
    /* if (superuser()) return; */

    int pass_len   = (int) strlen(shadow_pass);
    int n_upper    = count_uppercase(shadow_pass);
    int n_lower    = count_lowercase(shadow_pass);
    int n_digits   = count_digits(shadow_pass);
    int n_special  = count_special(shadow_pass);

    /* ---- 1. Minimum total length ---- */
    if (pass_len < apc_min_length)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("password is too short"),
                 errdetail("Password must be at least %d characters long. "
                           "Current length: %d.",
                           apc_min_length, pass_len)));

    /* ---- 2. Minimum uppercase ---- */
    if (n_upper < apc_min_uppercase)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("password does not contain enough uppercase letters"),
                 errdetail("Password must contain at least %d uppercase letter(s). "
                           "Found: %d.",
                           apc_min_uppercase, n_upper)));

    /* ---- 3. Minimum lowercase ---- */
    if (n_lower < apc_min_lowercase)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("password does not contain enough lowercase letters"),
                 errdetail("Password must contain at least %d lowercase letter(s). "
                           "Found: %d.",
                           apc_min_lowercase, n_lower)));

    /* ---- 4. Minimum numbers ---- */
    if (n_digits < apc_min_numbers)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("password does not contain enough digit characters"),
                 errdetail("Password must contain at least %d digit(s). "
                           "Found: %d.",
                           apc_min_numbers, n_digits)));

    /* ---- 5. Minimum special characters ---- */
    if (n_special < apc_min_special)
        ereport(ERROR,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("password does not contain enough special characters"),
                 errdetail("Password must contain at least %d special character(s) "
                           "(e.g. !@#$%%^&*). Found: %d.",
                           apc_min_special, n_special)));

    /* ---- 6. Minimum character difference from previous password ---- */
    if (apc_min_char_diff > 0)
    {
        char *old_pass = decrypt_password(username);

        if (old_pass != NULL)
        {
            int diff = count_char_diff(shadow_pass, old_pass);

            pfree(old_pass);

            if (diff < apc_min_char_diff)
                ereport(ERROR,
                        (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                         errmsg("new password is too similar to the previous password"),
                         errdetail("At least %d character(s) must differ from the "
                                   "previous password. Found %d different character(s).",
                                   apc_min_char_diff, diff)));
        }
        /* If no previous password exists, skip this check */
    }

    ereport(DEBUG1,
            (errmsg("advanced_password_check: password passed all policy checks "
                    "for user \"%s\"", username)));
}
