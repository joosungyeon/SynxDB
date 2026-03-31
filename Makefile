# Makefile for advanced_password_check extension
# Requires PostgreSQL 14 development headers (postgresql14-devel or equivalent)
#
# Usage:
#   make
#   make install
#   make installcheck   (runs regression tests)

MODULE_big  = advanced_password_check
OBJS        = advanced_password_check.o

EXTENSION   = advanced_password_check
DATA        = advanced_password_check--1.0.sql
PGFILEDESC  = "advanced_password_check - password policy enforcement for SynxDB"

# Regression tests
REGRESS      = advanced_password_check_test
REGRESS_OPTS = --inputdir=test

# Documentation
# DOCS = README.md

PG_CONFIG   ?= pg_config
PGXS        := $(shell $(PG_CONFIG) --pgxs)

include $(PGXS)

# Strip GCC flags unsupported by older system GCC
CFLAGS := $(filter-out -Wimplicit-fallthrough=3,      $(CFLAGS))
CFLAGS := $(filter-out -Wcast-function-type,           $(CFLAGS))
CFLAGS := $(filter-out -Werror=implicit-fallthrough=3, $(CFLAGS))
CFLAGS := $(filter-out -Wno-format-truncation,         $(CFLAGS))
CFLAGS := $(filter-out -Wno-stringop-truncation,       $(CFLAGS))
CFLAGS := $(filter-out -Wno-unused-but-set-variable,   $(CFLAGS))

# dblink 헤더 경로 추가
CFLAGS += -I$(shell $(PG_CONFIG) --includedir-server)/extension
