-- advanced_password_check--1.0.sql
-- Extension installation script
-- SynxDB / PostgreSQL 14

-- Superuser-only guard
DO $$
BEGIN
  IF NOT pg_catalog.pg_has_role(current_user, 'pg_read_all_settings', 'USAGE') THEN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = current_user AND rolsuper) THEN
      RAISE EXCEPTION 'advanced_password_check must be installed by a superuser';
    END IF;
  END IF;
END;
$$;

-- The extension is implemented entirely in C (shared library).
-- This SQL file documents the GUC parameters available to superusers.
-- No SQL objects (tables, functions) are created; all logic lives in the hook.

-- -------------------------------------------------------------------------
-- GUC Parameters Summary (set in postgresql.conf or via SET/ALTER SYSTEM)
-- -------------------------------------------------------------------------
--
-- advanced_password_check.min_length     (integer, default 9)
--   Minimum total number of characters required.
--
-- advanced_password_check.min_uppercase  (integer, default 2)
--   Minimum number of uppercase ASCII letters required.
--
-- advanced_password_check.min_lowercase  (integer, default 2)
--   Minimum number of lowercase ASCII letters required.
--
-- advanced_password_check.min_numbers    (integer, default 2)
--   Minimum number of digit characters (0-9) required.
--
-- advanced_password_check.min_special    (integer, default 2)
--   Minimum number of special/punctuation characters required.
--   Special characters are any printable non-alphanumeric characters,
--   e.g. !@#$%^&*()-_=+[]{};:'",.<>?/\|`~
--
-- advanced_password_check.min_char_diff  (integer, default 4)
--   Minimum number of character positions that must differ from the
--   previous stored password. Set to 0 to disable this check.
--
-- -------------------------------------------------------------------------
-- Example configuration in postgresql.conf:
-- -------------------------------------------------------------------------
--   shared_preload_libraries = 'advanced_password_check'
--   advanced_password_check.min_length    = 9
--   advanced_password_check.min_uppercase = 2
--   advanced_password_check.min_lowercase = 2
--   advanced_password_check.min_numbers   = 2
--   advanced_password_check.min_special   = 2
--   advanced_password_check.min_char_diff = 4
--
-- -------------------------------------------------------------------------
-- Runtime configuration (superuser only):
-- -------------------------------------------------------------------------
--   SET advanced_password_check.min_length    = 12;
--   SET advanced_password_check.min_uppercase = 3;
--   ALTER SYSTEM SET advanced_password_check.min_special = 3;
--   SELECT pg_reload_conf();
-- -------------------------------------------------------------------------

-- Create a view to easily inspect current policy settings
CREATE OR REPLACE VIEW advanced_password_check_policy AS
SELECT
    name,
    setting,
    unit,
    short_desc,
    min_val,
    max_val
FROM pg_settings
WHERE name LIKE 'advanced_password_check.%'
ORDER BY name;

COMMENT ON VIEW advanced_password_check_policy IS
    'Current advanced_password_check policy configuration';

GRANT SELECT ON advanced_password_check_policy TO PUBLIC;
