# advanced_password_check

**Password policy enforcement extension for SynxDB4 (PostgreSQL 14-based MPP)**
- Built for SynxDB (Apache Cloudberry / PostgreSQL 14-based MPP)

---

## Features

| Policy Rule | GUC Parameter | Default |
|---|---|---|
| Minimum total length | `advanced_password_check.min_length` | 9 |
| Minimum uppercase letters | `advanced_password_check.min_uppercase` | 2 |
| Minimum lowercase letters | `advanced_password_check.min_lowercase` | 2 |
| Minimum digit characters | `advanced_password_check.min_numbers` | 2 |
| Minimum special characters | `advanced_password_check.min_special` | 2 |
| Minimum chars different from previous password | `advanced_password_check.min_char_diff` | 4 |

Special characters are any printable non-alphanumeric characters, including:
`! @ # $ % ^ & * ( ) - _ = + [ ] { } ; : ' " , . < > ? / \ | \` ~`

---

## Requirements

- SynxDB
- Superuser privileges for installation and policy configuration
- devtoolset-10-gcc
- devtoolset-10-gcc-c++ 
- openssl-devel


---

## Installation

### 1. Build and install

```bash
# Clone or extract the extension source
cd advanced_password_check

# Point to your PostgreSQL/SynxDB pg_config if not on PATH
export PG_CONFIG=/path/to/synxdb/bin/pg_config

make
make install
```

This installs:
- `$libdir/advanced_password_check.so` — shared library
- `$sharedir/extension/advanced_password_check.control`
- `$sharedir/extension/advanced_password_check--1.0.sql`

### 2. Configure `postgresql.conf`

Add the extension to `shared_preload_libraries` — **this is mandatory**

```ini
# postgresql.conf
shared_preload_libraries = 'advanced_password_check'

# Optional: set policy (can also be set at runtime by superusers)
advanced_password_check.min_length    = 9
advanced_password_check.min_uppercase = 2
advanced_password_check.min_lowercase = 2
advanced_password_check.min_numbers   = 2
advanced_password_check.min_special   = 2
advanced_password_check.min_char_diff = 4
```

If you already have other libraries in `shared_preload_libraries`, append with a comma:

```ini
shared_preload_libraries = 'other_lib,advanced_password_check'
```

### 3. Restart SynxDB

``` cli
gpadmin $ gpstop -afr
```

### 4. Install the extension in the target database

``` sql
-- Connect as superuser
userdb =# CREATE EXTENSION advanced_password_check;
```

## Usage

### Inspecting the current policy

``` sql
userdb =# SELECT name, setting, short_desc FROM advanced_password_check_policy;

              name                         | setting | ...
-------------------------------------------+---------+
 advanced_password_check.min_char_diff     | 4       |
 advanced_password_check.min_length        | 9       |
 advanced_password_check.min_lowercase     | 2       |
 advanced_password_check.min_numbers       | 2       |
 advanced_password_check.min_special       | 2       |
 advanced_password_check.min_uppercase     | 2       |
```

### Changing policy at runtime (superuser only)

``` sql
-- Increase minimum length
userdb =# SET advanced_password_check.min_length = 12;

-- Persist the change across restarts
userdb =# ALTER SYSTEM SET advanced_password_check.min_length = 12;
userdb =# SELECT pg_reload_conf();

-- Disable the char-diff check entirely
userdb =# SET advanced_password_check.min_char_diff = 0;
```

### Setting passwords (enforced by policy)

``` sql
-- This will be checked against the active policy:
userdb =# CREATE ROLE myuser PASSWORD 'MySecure@Pass99';

userdb =# ALTER ROLE myuser PASSWORD 'NewPass!!2024xZ';
```

### Example rejection messages

``` sql
ERROR:  password is too short
DETAIL: Password must be at least 9 characters long. Current length: 6.

ERROR:  password does not contain enough uppercase letters
DETAIL: Password must contain at least 2 uppercase letter(s). Found: 1.

ERROR:  password does not contain enough special characters
DETAIL: Password must contain at least 2 special character(s) (e.g. !@#$%^&*). Found: 0.

ERROR:  new password is too similar to the previous password
DETAIL: At least 4 character(s) must differ from the previous password. Found 1 different character(s).
```

---

## Important Notes

### Pre-hashed passwords

If a client sends a password already hashed (MD5 or SCRAM), the extension **cannot**
inspect its character composition and will emit a `NOTICE` then skip policy enforcement.
This is consistent with Greenplum's behavior.

To ensure policy enforcement always applies, configure clients to send plaintext passwords
and let the server handle hashing:

```ini
# postgresql.conf
password_encryption = scram-sha-256   # recommended
```

### Superuser bypass

By default, the extension does **not** bypass checks for superusers (the relevant code
is present but commented out). To allow superusers to set any password, uncomment this
block in `advanced_password_check.c`:

```c
/* if (superuser()) return; */
```

### min_char_diff and hashed passwords

The `min_char_diff` check compares the new plaintext password against the stored
`pg_authid.rolpassword` value. When the stored password is hashed (SCRAM/MD5), the
comparison is between plaintext and the hash string — this still prevents trivially
incremental changes but is not a true plaintext-to-plaintext comparison. For full
effectiveness, consider using a password history table (see "Extending the extension").

### MPP / Coordinator-only execution

In a SynxDB MPP cluster, password DDL executes only on the coordinator node.
The extension hook fires on the coordinator. No changes are needed for segment nodes,
but `shared_preload_libraries` should be set consistently on all nodes.

---

## Running Regression Tests

```bash
make installcheck
```

---

## Extending the Extension

### Password history table

To maintain a true history of previous passwords and enforce `min_char_diff` against
multiple previous passwords, create a history table and extend the C hook:

```sql
CREATE TABLE password_history (
    rolname   TEXT NOT NULL,
    pass_hash TEXT NOT NULL,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

Then in the C hook, query this table (via SPI) before accepting the new password.

### Custom special character sets

Modify `is_special_char()` in `advanced_password_check.c` to restrict or expand
which characters are considered "special" based on your organization's policy.

---

## File Structure

```
advanced_password_check/
├── advanced_password_check.c           # Main extension source (C)
├── advanced_password_check.control     # Extension metadata
├── advanced_password_check--1.0.sql    # SQL installation script + policy view
├── Makefile                            # Build script (PGXS)
└── README.md                           # This file

```

---

## License
PostgreSQL License
