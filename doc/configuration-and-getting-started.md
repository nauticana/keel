# Configuration and Getting Started

Runtime configuration, application bootstrap, REST wiring, and background workers.

## Runtime Configuration

Most runtime settings live in the database, not in flags or recompiled constants.
`config.LoadRows` resolves the whole flag catalog from two basis tables in one
query; each embedded config's `Apply` parses its own flags from that result.
Keel's section is read as `config.Config()`:

- **`application_config_flag`** — the flag catalog (framework-seeded): `id`,
  `data_type` (`string | int | int64 | float | duration` (seconds) `| bool`),
  `needs_restart`, `default_value`, `description`.
- **`application_config_value`** — per-node assignments: `(node_id, flag_id) ->
  assigned_value`. `node_id` identifies the runtime node/process (matched
  against `--node_id`). Most single-node deployments use 0; multi-node
  deployments assign values per node. The reserved **`node_id = -1`** is a
  shared fallback bucket: a flag with no row for the running node inherits its
  `-1` row, so a value identical across every node is written once instead of
  per node. Absent both, `application_config_flag.default_value` applies.

`LoadRows` resolves each flag **node row → `-1` shared row → `default_value`** (two
LEFT JOINs, `COALESCE` picking the precedence) so every catalogued flag
resolves. `-1` is a config-only sentinel — it never seeds the id generator, so
`--node_id` itself always stays a real writer id in `[0, 1023]`. **Only bootstrap settings stay as
`--flags`** — how to reach the DB, the secret provider, the log sink, and
`--node_id`. Everything else moves to the tables. **Store only non-secret values
here**; a flag like `oauth_signing_key_secret` holds a secret *name*, resolved
through the `SecretProvider`.

```go
// Keel-only binary, after the DB connection is up:
rows, err := config.LoadRows(ctx, db, *common.NodeId)
if err != nil {
    log.Fatal(err)
}
if err := config.ApplyRows(rows); err != nil {
    log.Fatal(err) // never start or print from a partial config
}
if *common.PrintConfig {
    if err := config.Print(os.Stdout, rows); err != nil {
        log.Fatal(err)
    }
    return
}
```

`config.Print` lists each `--flag` with `(set)` or `(default)`. Each catalog
entry reports its exact source as `(node)`, `(shared)`, or `(default)` and shows
the catalog default beside an assignment. Values whose key contains `password`,
`secret`, `credential`, or `private` print as `***` (`*_mode` keys excepted).

The loader fails hard on any DB, catalog, parsing, or validation problem, and
nothing is published until every section applied cleanly — a failed load or
reload leaves the prior configuration active.

**Composing several repositories.** Each repository owns a config type that
embeds `config.AbstractConfig` (the flag parser), an `Apply` method parsing its
own flags — the `config.ApplicationConfig` interface — and an atomic reader:

```go
// package scout
type ScoutConfig struct {
    config.AbstractConfig
    Endpoint string
}

var _ config.ApplicationConfig = (*ScoutConfig)(nil)

var activeConfig atomic.Pointer[ScoutConfig]

func init() { activeConfig.Store(&ScoutConfig{}) }

func Config() *ScoutConfig { return activeConfig.Load() }

func SetConfig(c *ScoutConfig) { activeConfig.Store(c) }

func (c *ScoutConfig) Apply(rows config.ConfigRows) error {
    c.Endpoint = c.String(rows, "scout_endpoint")
    return c.ParseErr()
}
```

The `AbstractConfig` readers (`String`, `Int`, `Int64`, `Float`, `Bool`,
`Duration`) resolve assigned value → catalog default, record a missing catalog
row, and label malformed values with the flag id; `ParseErr` reports everything
accumulated, so any missing or malformed flag aborts the load with every
problem named at once.

The deployable application defines its own section the same way. Its loader
queries the catalog once, applies every section, and publishes each one only
after all of them succeeded:

```go
// package seo
type SeoConfig struct {
    config.AbstractConfig
    FeatureX string
    MaxFoo   int
}

func (c *SeoConfig) Apply(rows config.ConfigRows) error {
    c.FeatureX = c.String(rows, "feature_x")
    c.MaxFoo = c.Int(rows, "max_foo")
    return c.ParseErr()
}

var activeConfig atomic.Pointer[SeoConfig]

func init() { activeConfig.Store(&SeoConfig{}) }

func Config() *SeoConfig { return activeConfig.Load() }

func LoadConfig(ctx context.Context, db port.DatabaseRepository) error {
    rows, err := config.LoadRows(ctx, db, *common.NodeId)
    if err != nil {
        return err
    }
    kc := &config.KeelConfig{}
    sc := &scout.ScoutConfig{}
    ec := &SeoConfig{}
    for _, ac := range []config.ApplicationConfig{kc, sc, ec} {
        if err := ac.Apply(rows); err != nil {
            return err
        }
    }
    config.SetConfig(kc)
    scout.SetConfig(sc)
    activeConfig.Store(ec)
    return nil
}
```

Keel code reads `config.Config()`, scout code `scout.Config()`, seo code
`seo.Config()`. Seed every repository's owned flags into
`application_config_flag` alongside keel's.

**Runtime reload.** `application_config_flag` is exposed as a REST resource
(with `application_config_value` nested as its child) under a `setup` menu item,
and carries a non-record-specific **RELOAD** table action (`handler.ReloadConfig`,
wired to `config.ReloadFunc`) that re-applies config live. Enable it after the
database is available:

```go
config.ReloadFunc = func(ctx context.Context) error {
    return seo.LoadConfig(ctx, db)
}
```

The catalog is seed-managed and display-only in the UI (`needs_restart` and `default_value` are
marked read-only in `column_display_attribute`; `id` is the PK) — admins assign
per-node `application_config_value` rows, which are full CRUD. `needs_restart`
marks construction-captured settings (server wiring, provider selection,
connection URLs, singleton clients) that a RELOAD cannot re-apply; everything
else is read per request/call through its repository's `Config()` and takes
effect on RELOAD.
The catalog's `default_value` is the only default — there are no compiled
fallbacks, and a malformed value fails the load.

## Quick Start

### 1. Add the dependency

```bash
go get github.com/nauticana/keel@<version>
```

### 2. Bootstrap your application

```go
package main

import (
    "context"
    "flag"
    "log"

    "github.com/nauticana/keel/common"
    "github.com/nauticana/keel/data"
    "github.com/nauticana/keel/logger"
    "github.com/nauticana/keel/pgsql"
    "github.com/nauticana/keel/secret"
)

func main() {
    flag.Parse()
    ctx := context.Background()

    // 1. Logger
    journal, _ := logger.NewApplicationLogger("myapp")
    defer journal.Close()

    // 2. Secrets
    secrets, _ := secret.NewSecretProvider(ctx)

    // MustGet is for required boot secrets, never request paths: it exits
    // the process when the secret is unavailable.
    jwtSecret := secret.MustGet(ctx, secrets, "jwt_secret")

    // 3. Bigint ID generator for collision-free federated ids.
    gen, err := data.NewNodeSnowflake() // --node_id, EpochMs2026
    if err != nil { log.Fatalf("snowflake: %v", err) }

    // 4. Database
    db, _ := pgsql.NewPgSQLDatabase(ctx, secrets, gen)

    // 5. Wire your controller and run
    _ = jwtSecret // pass to user.NewLocalUserService(...)
    // ...
}
```

### 3. Use the REST engine

```go
import (
    "errors"
    "fmt"

    "github.com/nauticana/keel/common"
    "github.com/nauticana/keel/handler"
    "github.com/nauticana/keel/port"
    "github.com/nauticana/keel/rest"
)

// Initialize REST service — reads API definitions from DB. Journal enables the
// startup grant audit: a TABLE grant with no generic CRUD route (no active
// rest_api_header row) and a mounted master table no role can reach are each
// logged as a Warning.
restService := &rest.RestService{Journal: journal}
apis, reports, _ := restService.Init(ctx, db)

// Optional: validate a generic CRUD batch after all parent/child writes are
// visible, but before the transaction commits. Returning an error rolls back
// the entire batch and is surfaced by RestHandler as a failed POST.
validationQueries := map[string]string{
    "validate_schedule": `SELECT COUNT(*) FROM commission_rule WHERE ...`,
}
apis["commission_rule"].SetTransactionalWriteHook(
    func(ctx context.Context, tx port.TxView, partnerID int64, userID int,
        table string, items []any) error {
        queryTx, ok := tx.(port.TxQueryView)
        if !ok {
            return fmt.Errorf("transactional named queries are unavailable")
        }
        result, err := queryTx.QueryService(validationQueries).
            Query(ctx, "validate_schedule", partnerID)
        if err != nil {
            return err
        }
        if common.AsInt64(result.Rows[0][0]) != 0 {
            return errors.New("commission schedule has a gap")
        }
        return nil
    },
)

// Create handlers for each API
for name, api := range apis {
    h := &handler.RestHandler{
        AbstractHandler: handler.AbstractHandler{UserService: userSvc},
        Api:             *api,
    }
    backend.Handle(map[string]func(w, r){
        "/api/v1/" + name:          h.Get,
        "/api/v1/" + name + "/list": h.List,
        "/api/v1/" + name + "/post": h.Post,
    })
}
```

`TransactionalWriteHook` is the financial/business-invariant hook for
auto-CRUD. `RelationAPI.Post` first writes the complete nested batch through
transaction-bound `TableService` instances, then calls the hook, and commits
only when the hook returns nil. PostgreSQL's transaction view implements the
optional `port.TxQueryView`, allowing named SQL to inspect the proposed state.
This is different from `handler.RestHandler.PostWrite`: `PostWrite` runs after
commit and is appropriate for cache invalidation or notifications, never for
validation that must roll back the write.

**List envelope.** `RestHandler.List` never answers with a bare JSON array:
successful responses have the shape
`{"data":{"items":[],"limit":50,"offset":0,"total":0},"meta":{...}}`.
Decode rows from `data.items` (or `items` after your HTTP client unwraps `data`).
Decoding directly into an array is incorrect; the resulting error or empty
state depends on the client's decoder.

**List pagination.** `RestHandler.List` takes `?limit=` / `?offset=` (default
`default_list_page_size`, hard-capped at `max_list_page_size`) and `?order=`,
and fills `data` with `{items, limit, offset, total}` where `total` is the unpaged
count. The bounds reach SQL as `LIMIT` / `OFFSET` when the bound table service
implements the optional `port.PagedTableService` — PostgreSQL's does — so the
response cap is also a read cap rather than a slice taken after a full-table
scan (KR-006). A paged read always gets a total order: the primary key is
appended to whatever `?order=` asked for, because rows tied on the caller's
column could otherwise repeat or vanish as a client walks offsets. A
`TableService` that does not implement the capability keeps working — callers
fall back to reading the collection and slicing it, and that path appends the
key too (via `port.PageRequest.StableOrderBy`), so paging is deterministic
either way. Because the fallback passes the tie-break through the `orderby`
string, a custom `TableService.Get` must accept the comma-separated `?order=`
grammar below to page correctly. `?order=` accepts
comma-separated `column [ASC|DESC]` terms (`?order=amount DESC, id`); a term
that doesn't resolve to a declared column is rejected, never silently dropped.

Every POST item must carry `op_code` (`I` insert, `U` update, `D` delete, `R`
unchanged parent whose children carry their own); a missing or unknown code is
400. A sole integer key with a `table_sequence_usage` row takes the sequence's
`nextval`; without one (and without a DB default) an insert that carries no
positive id takes the next id from the repository's `port.BigintGenerator`
(Snowflake by default), so surrogate keys are generated the same way on any
database and stay unique across nodes. A caller-supplied positive id is kept.

Unresolvable `?order=` terms and filter columns are `model.NewBadRequest`
(400), not 500: the value is caller-controlled, so the server is healthy and
the client is the one who must fix the request. This also makes the failure
actionable — `writeError` sanitizes 5xx bodies and journals them, so at 500 the
caller could not see *which* column was rejected and every query-string typo
landed in the operator error log. It matches how the handler already answers an
unknown *filter* field in `castFilterValues`.

### 4. Run a background worker

For binaries that don't need custom database/quota wiring, embed `worker.AbstractWorker` and call `w.Run(ctx, w)` — it is the one-call entry point:

```go
import (
    "context"
    "flag"
    "log"

    "github.com/nauticana/keel/worker"
)

type AnalyticsWorker struct {
    worker.AbstractWorker // supplies GetHealthcheckPort + Run; reads .Secret in ProcessQueue
}

func (w *AnalyticsWorker) GetOLTPQueries() map[string]string { return analyticsQueries }
func (w *AnalyticsWorker) ProcessQueue(ctx context.Context, journal logger.ApplicationLogger,
    db data.DatabaseRepository, quota port.QuotaService, qs data.QueryService) { /* ... */ }

func main() {
    flag.Parse()
    w := &AnalyticsWorker{worker.AbstractWorker{Caption: "analytics", Interval: 3600, HCPort: 8108}}
    if err := w.Run(context.Background(), w); err != nil {
        log.Fatal(err)
    }
}
```

`Run` builds the standard logger, secret provider, snowflake id generator, pgsql database, and `QuotaServiceDb`, then loads configuration after the database is up; a load failure aborts startup. Its default `config.LoadConfig` loads KeelConfig alone. Applications with a composite config set the worker's `LoadConfig` hook to construct and load a fresh composite instance. It then publishes the secret provider on `.Secret`, wires everything into a `JobExecutor`, and runs. The embedder implements only `GetOLTPQueries` plus **one processing contract** — `worker.JobWorker` (`ProcessQueue`, shown above) or `worker.QueueWorker` (`QueueQueries` + `HandleJob`, see the next section); `GetHealthcheckPort` comes from `AbstractWorker`. The `, w` is the concrete instance ("self") — Go has no virtual dispatch, so the embedded base can't reach the embedder's processing methods without it.

For infrequent jobs driven by an external cron / systemd timer (weekly or monthly payouts), use `worker.RunOnce(ctx, loadConfig, pick)` instead of a daemon: it composes the same runtime pieces minus the healthcheck listener, registry heartbeat, and ticker loop, runs one `ProcessQueue` pass, and exits. A nil `loadConfig` loads KeelConfig alone; pass a hook for a composite config. `pick` runs after config load with the resolved `DatabaseRepository`, so job selection can read config flags and open a second query catalog or a `QuotaService` on the same database; it returns the `JobWorker` plus the journal caption.

Use `JobExecutor` directly when you need to inject extra services or a non-default database flavor:

```go
executor := &worker.JobExecutor{
    Caption:     "analytics",
    Interval:    3600,
    Journal:     journal,
    Worker:      &yourworker.AnalyticsWorker{},
    NewDatabase: func(ctx context.Context, sp port.SecretProvider) (port.DatabaseRepository, error) {
        return pgsql.NewPgSQLDatabase(ctx, sp, gen)
    },
    NewQuota: func(db port.DatabaseRepository) port.QuotaService {
        return &myCustomQuotaService{Repo: db}
    },
}
executor.Run(ctx, secrets)
```

### How the background job scheduler works

keel's background processing is **three layers, each at a different cadence**. Keeping them separate is what makes the design robust: each layer is independently testable and reusable, and a single bad job can never take down the daemon.

```
main: w := &PublishWorker{AbstractWorker{Caption, Interval, HCPort}}; w.Run(ctx, w)
  │
  ├─ AbstractWorker.Run            ── once at startup ──
  │     logger → secret provider (published on .Secret) → snowflake → db → config Load → storage → JobExecutor → Run
  │
  ├─ JobExecutor                   ── the PROCESS: 1 per binary, runs forever ──
  │     health server, service-registry + heartbeat, build db/quota/qs ONCE, panic barrier, ticker
  │     every Interval seconds → one tick:
  │        │
  │        ├─ JobLoop              ── the DRAIN of ONE queue: per tick ──
  │        │     Reclaim(ctx)            demote stale 'A' claims (crashed runs) → 'P'
  │        │     Run(ctx, handle):       poll pending → claim each atomically → if won:
  │        │        │
  │        │        └─ HandleJob   ── ONE job: per claimed row ──
  │        │              the worker's business logic for a single job; returns error
```

| Layer | Type | Scope / cadence | Responsibility |
|---|---|---|---|
| Process | `JobExecutor` | one per binary, runs forever | health check, service registry + heartbeat, build db/quota/QS once, ticker, panic recovery |
| Drain | `JobLoop` | one per queue, per tick | reclaim stale claims, poll pending, claim atomically, dispatch each claimed job |
| One job | `HandleJob` / `ProcessQueue` | per claimed row / per tick | the worker's business logic |

**Two worker contracts.** A worker implements exactly one:

- **`QueueWorker`** (recommended for queue drainers) — supply the queue identity and one-job logic; the framework owns the drain. `JobExecutor` detects the contract, builds the `JobLoop` once, and drives `Reclaim` + `Run(HandleJob)` each tick:

  ```go
  type PublishWorker struct{ worker.AbstractWorker }

  func (w *PublishWorker) GetOLTPQueries() map[string]string { return publishQueries }
  func (w *PublishWorker) QueueQueries() (pending, claim, reclaim, name string) {
      return qPendingPublish, qClaimPublish, qReclaimPublish, "publish"
  }
  func (w *PublishWorker) HandleJob(ctx context.Context, journal logger.ApplicationLogger,
      db data.DatabaseRepository, quota port.QuotaService, qs data.QueryService,
      jobID int64, row []any) error {
      // process exactly one job; return err to surface it loudly (framework logs it)
  }
  ```

- **`JobWorker`** (custom / multi-queue / non-queue) — own the whole per-tick pass in `ProcessQueue`. Use this when a tick drains several queues (run multiple `JobLoop`s yourself) or does non-queue work (aggregation, sweeps).

**Why `JobLoop` is a separate class, not folded into `JobExecutor`:** (1) one process can drain several queues — N loops per tick; (2) it is unit-testable with a fake `QueryService` (claim-won / claim-lost / reclaim / handler-error paths) with no HTTP/registry/ticker scaffolding; (3) it is reusable outside a daemon (a CLI one-shot drain or backfill). `JobExecutor` *drives* a `JobLoop`; it does not *become* one. The driver lives in `JobExecutor` because that is where the worker is held as an interface, so it can call `HandleJob` polymorphically.

**Queue table convention.** Status flows `P` (pending) → `A` (active/claimed) → done, with `R` for retry. The claim is an atomic `UPDATE … SET status='A', claimed_at=CURRENT_TIMESTAMP WHERE id=? AND status IN ('P','R') RETURNING id` so two nodes can't both win, and it stamps its own time: `Reclaim` ages a claim from that stamp, never from a scheduled or created time, which would make a long-queued job look stale while it runs. `Reclaim` returns an expired claim (a worker that crashed mid-job) to `P` only for idempotent work; a job with an outside side effect may already have taken effect, so its reclaim moves it to a terminal unknown-outcome status for reconciliation. Route a retryable failure to `R` with a `scheduled_time`, and have the pending query select `R` rows whose time has arrived — backoff is a handler concern, not the loop's.

## Adopting a release

Upgrade one tagged release at a time, reading its entry in [`migration_guide.json`](../migration_guide.json); the documentation describes only the current state.

- Apply every breaking item: change every caller in the same upgrade, without keeping the old behavior behind a local wrapper.
- Regenerate the schema from `schema/basis_pgsql.sql` on a disposable database, then apply the listed column and seed changes to stored data in the order given. Never alter a keel table beyond what the entry states.
- Mount handler routes with `HttpBackend.Handle`, so security headers, CORS and the access log apply; a page keel renders, such as the OAuth consent page, sets its own headers, and a custom consent page sets its own `Content-Security-Policy` with a `form-action` that allows the post and the client's redirect.
- keel's stores enforce bindings (connect state, pending client counts, code replay); an application substituting its own `port` or `client` implementation takes on the rules the interface comment states.
- Check the entry for new or stricter flags and set them per environment; a changed route contract names the matching frontend change.
- Verify with `go test ./...` and the `-sqlsmoke` packages against a disposable database before deploying.
