.PHONY: build clean gen-pgsql gen-mysql gen-schema verify-schema test vet

# Default build target — produces the schemagen binary used by gen-* / verify-schema.
build:
	go build -o bin/schemagen ./cmd/schemagen/

clean:
	rm -rf bin/

# ---------------------------------------------------------------------------
# Schema artifacts
# ---------------------------------------------------------------------------
# `gen-pgsql` and `gen-mysql` regenerate the committed reference DDL from
# the YAML source under schema/basis and schema/security. The output
# files are build artifacts — they MUST be regenerated whenever a YAML
# in schema/ changes. `verify-schema` is the CI gate that fails the
# build if the committed files have drifted from the YAML source.
#
# Downstream consumers can read schema/basis_pgsql.sql directly to diff
# keel upgrades against the previous release without running schemagen
# themselves.

# SCHEMA_DIRS is the comma-separated list of input directories the
# generator walks. Order matters for FK resolution: basis must come
# before security since security tables reference basis tables.
SCHEMA_DIRS := schema/basis,schema/security

gen-pgsql: build
	./bin/schemagen -dialect pgsql -input $(SCHEMA_DIRS) -out schema/basis_pgsql.sql

gen-mysql: build
	./bin/schemagen -dialect mysql -input $(SCHEMA_DIRS) -out schema/basis_mysql.sql

# Regenerate both dialects in one shot — the common case after a YAML edit.
gen-schema: gen-pgsql gen-mysql

# verify-schema fails when the committed DDL is out of sync with the YAML
# source. CI runs this on every PR so an edit to schema/*.yml that
# forgets to refresh the .sql artifacts is caught at the PR stage rather
# than landing as an undocumented schema drift.
verify-schema: build
	@./bin/schemagen -dialect pgsql -input $(SCHEMA_DIRS) -out /tmp/keel_basis_pgsql.sql >/dev/null
	@./bin/schemagen -dialect mysql -input $(SCHEMA_DIRS) -out /tmp/keel_basis_mysql.sql >/dev/null
	@diff -u schema/basis_pgsql.sql /tmp/keel_basis_pgsql.sql || \
		{ echo "ERROR: schema/basis_pgsql.sql out of sync with YAML — run 'make gen-pgsql'"; exit 1; }
	@diff -u schema/basis_mysql.sql /tmp/keel_basis_mysql.sql || \
		{ echo "ERROR: schema/basis_mysql.sql out of sync with YAML — run 'make gen-mysql'"; exit 1; }
	@rm -f /tmp/keel_basis_pgsql.sql /tmp/keel_basis_mysql.sql
	@echo "schema artifacts in sync with YAML"

# ---------------------------------------------------------------------------
# Standard developer targets
# ---------------------------------------------------------------------------
test:
	go test ./...

vet:
	go vet ./...
