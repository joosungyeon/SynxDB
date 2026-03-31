# advanced_password_check

SynxDB (PostgreSQL 14 기반 MPP) 용 패스워드 정책 enforcement extension

## 기능

| 정책 | GUC 파라미터 | 기본값 |
|---|---|---|
| 최소 길이 | `advanced_password_check.min_length` | 9 |
| 최소 대문자 | `advanced_password_check.min_uppercase` | 2 |
| 최소 소문자 | `advanced_password_check.min_lowercase` | 2 |
| 최소 숫자 | `advanced_password_check.min_numbers` | 2 |
| 최소 특수문자 | `advanced_password_check.min_special` | 2 |
| 현재 패스워드 재사용 방지 | `advanced_password_check.no_reuse` | true |

## 동작 방식

- `CREATE ROLE` / `ALTER ROLE ... PASSWORD` 실행 시 `check_password_hook` 발동
- 평문 패스워드를 받아 복잡도 정책 검사
- `get_role_password()` + `plain_crypt_verify()` 로 현재 저장된 패스워드와 비교
  - SCRAM-SHA-256이어도 저장된 salt를 재사용해 정확히 동일 여부 판별
  - 평문 저장 없이 안전하게 비교 가능

## 빌드 환경

- SynxDB 4.x / PostgreSQL 14
- GCC 10+ (devtoolset-10 이상 권장)
- `openssl-devel` 패키지

## 설치

```bash
# 1. 빌드
make PG_CONFIG=/usr/local/synxdb4/bin/pg_config

# 2. 설치 (코디네이터)
make install PG_CONFIG=/usr/local/synxdb4/bin/pg_config

# 3. 세그먼트 노드 배포
gpscp -f /data/staging/hostfile advanced_password_check.so \
    =:/usr/local/synxdb4/lib/postgresql/

# 4. postgresql.conf 설정
shared_preload_libraries = 'advanced_password_check'
advanced_password_check.min_length    = 9
advanced_password_check.min_uppercase = 2
advanced_password_check.min_lowercase = 2
advanced_password_check.min_numbers   = 2
advanced_password_check.min_special   = 2
advanced_password_check.no_reuse      = true

# 5. 재시작
gpstop -r -a

# 6. Extension 설치
psql -d <dbname> -c "CREATE EXTENSION advanced_password_check;"
```

## 정책 변경

```sql
-- 즉시 적용
ALTER SYSTEM SET advanced_password_check.min_length = 12;
SELECT pg_reload_conf();

-- 현재 정책 확인
SELECT name, setting FROM advanced_password_check_policy;
```

## Credits

- Inspired by Greenplum `advanced_password_check`
- Based on PostgreSQL `check_password_hook` API
- Built for SynxDB (Apache Cloudberry / PostgreSQL 14-based MPP)
