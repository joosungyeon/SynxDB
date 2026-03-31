-- advanced_password_check--1.0.sql
-- SynxDB / PostgreSQL 14

-- 현재 정책 확인 뷰
CREATE OR REPLACE VIEW advanced_password_check_policy AS
SELECT
    name,
    setting,
    short_desc
FROM pg_settings
WHERE name LIKE 'advanced_password_check.%'
ORDER BY name;

GRANT SELECT ON advanced_password_check_policy TO PUBLIC;

COMMENT ON VIEW advanced_password_check_policy IS
    'Current advanced_password_check policy configuration';

-- =========================================================================
-- GUC 파라미터 안내
-- =========================================================================
-- advanced_password_check.min_length    (default: 9)    최소 길이
-- advanced_password_check.min_uppercase (default: 2)    최소 대문자 수
-- advanced_password_check.min_lowercase (default: 2)    최소 소문자 수
-- advanced_password_check.min_numbers   (default: 2)    최소 숫자 수
-- advanced_password_check.min_special   (default: 2)    최소 특수문자 수
-- advanced_password_check.no_reuse      (default: true) 현재 패스워드 재사용 방지
--
-- 런타임 변경 (슈퍼유저):
--   ALTER SYSTEM SET advanced_password_check.min_length = 12;
--   SELECT pg_reload_conf();
