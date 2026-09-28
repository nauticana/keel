# Go 1.25.3 → 1.27.1 upgrade analysis

keel and all known downstreams are on `go 1.25.3`, so the upgrade picks up both **Go 1.26** and **Go 1.27**. Sources: https://go.dev/doc/go1.26, https://go.dev/doc/go1.27.

## Verdict

The upgrade is low-risk and worth doing. keel has almost no code that the behavior changes affect (details below). The main gains are these language features for the OO style:

1. **Generic methods (1.27)**: type-parameterized accessors can live on concrete keel types. The biggest target is `model.QueryResult`.
2. **Self-referential generic constraints (1.26)**: the CRTP-style contract `type Entity[E Entity[E]] interface{…}`.
3. **Struct literal field selectors (1.27)**: an embedded ("inherited") field can be initialized directly in the literal.
4. **`errors.AsType[E]` (1.26)**: type-safe polymorphic error matching.
5. **`new(expr)` (1.26)**: removes the pointer helpers.

---

## 1. Language features for interfaces, abstraction, inheritance and polymorphism

### 1.1 Generic methods (1.27): the main addition

A method can now declare its own type parameters:

```go
func (qr *QueryResult) Col[T any](row int, name string) (T, error)
```

**Hard restriction:** an interface method cannot have type parameters, and a generic method cannot satisfy an interface method. The consequences for keel's port-first design:

| Place | Can use generic methods? | Why |
|---|---|---|
| `port.QueryService`, `port.TableService` and every other `port/*` interface | **No** | Interfaces cannot declare generic methods. `Query(...) (*model.QueryResult, error)` and `Get(...) ([]any, error)` keep their `any` signatures. |
| Concrete types that ports return (`model.QueryResult`, `content.Writers`, `cache.LRU`) | **Yes** | These are concrete, so a method can be generic. |
| `Abstract*`/`Base*` embed types (`AbstractHandler`, `AbstractTableService`) | Yes, but only as helpers | Promoted generic methods reach embedders. They are **not** part of any interface contract, so polymorphic callers cannot see them. |

**The pattern this enables:** keep the port non-generic (polymorphism stays at runtime), and put typed generic methods on the *concrete result type* the port returns. The caller gets static types without the interface becoming generic.

**Opportunities in keel:**

- **`model.QueryResult` typed accessors** ([model/query_result.go](model/query_result.go)). This is the highest-value item. Downstreams read results positionally with coercion helpers:

  | Repo | `.Rows[` indexing | `range x.Rows` | `common.As*` calls |
  |---|---|---|---|
  | seo | 372 | 234 | 1040 |
  | daxoom | 91 | 30 | 405 |
  | bdserp | 72 | 7 | 330 |

  Typical code today: `bcommon.AsInt64(row[0])`, which is positional, untyped and fails silently when a column is reordered. A generic method on a concrete type can replace it:

  ```go
  func (qr *QueryResult) Col[T any](row int, name string) (T, error)   // by column name, coerced via common.As*
  func (qr *QueryResult) Scan[T any](into func(Row) (T, error)) ([]T, error)
  ```

  Selecting by name removes the positional coupling. Returning a typed error on a missing column or failed coercion matches the "no silent failure" rule. Before 1.27 this had to be a free function (`model.Col[T](qr, …)`), which is not discoverable from the type. The change is additive (no break), and downstreams can migrate gradually.

- **`content.Writers` capability lookup** ([content/content.go:171](content/content.go#L171)). `capability[T]` is a free generic function with five thin wrapper methods (`Deleter`, `Uploader`, `Lister`, `Annotator`, `RedirectLister`). It can become a method, `func (w Writers) Capability[T any](provider, op string) (T, error)`. This is the Go analogue of a polymorphic "query interface" / `dynamic_cast` on the aggregate. **Recommendation:** keep the named wrappers. They carry the `op` text and read well. The generic method only helps if new capabilities keep appearing.

- **`cache.LRU[K,V]` / `ShardedLRU[K,V]`**: generic *types* already. A generic method such as `GetOrLoad[…]` gains little because the value type is fixed by the type parameter. No action.

- **Not candidates:** `data.ScanRows[T]` (it operates on `*sql.Rows`, a foreign type), `common.MergeMaps` (it operates on built-in maps), and `sqlsmoke.sortedKeys`.

### 1.2 Self-referential type constraints (1.26)

```go
type Entity[E Entity[E]] interface {
    Key() map[string]any
    Clone() E
}
func Upsert[E Entity[E]](ts port.TableService, e E) error
```

This is the Go version of CRTP / F-bounded polymorphism: an interface can require methods that return or accept *the implementing type itself*. It is useful for typed model contracts (`Clone() E`, `Merge(E) E`, `Less(E) bool`). Combined with 1.1, it allows a **typed adapter as a generic *type*** over the untyped port, for example `data.TypedTable[E Entity[E]]` wrapping `port.TableService` and returning `[]E` instead of `[]any`. A generic *type* can implement interfaces, so it keeps the port polymorphism.
**Recommendation:** treat this as optional and defer it. It overlaps with 1.1 (`QueryResult` accessors), which covers most of the pain with far less machinery, in line with "minimal types + explicit wiring".

### 1.3 Struct literal field selectors (1.27): inheritance ergonomics

A key in a struct literal can now be any valid field selector, not only a top-level name. With embedding-as-inheritance, fields promoted from `AbstractHandler`/`AbstractTableService` can be set in the literal directly. Before 1.27 you had to nest the embedded literal or assign after construction:

```go
type Base struct{ Name string }
type Derived struct{ Base; Extra int }

// before
d := Derived{Base: Base{Name: "x"}, Extra: 1}
// 1.27
d := Derived{Base.Name: "x", Extra: 1}
```

This removes the main friction of deep embedding hierarchies in constructors and tests. The new `go fix` modernizer **`embedlit`** rewrites existing nested literals automatically.

### 1.4 Generalized function type inference (1.27)

A generic function can be assigned to a variable, struct field or parameter of a matching function type without explicit instantiation. This helps with keel's "inject closures into framework types" rule. Passing `data.ScanRows`, `common.MergeMaps` or generic scanners as callbacks no longer needs `ScanRows[Foo]` spelled out.

### 1.5 `errors.AsType[E]` (1.26): polymorphic error handling

```go
if appErr, ok := errors.AsType[*AppError](err); ok { … }
```

It is type-safe, faster, and needs no pre-declared target variable. keel has 30 `errors.As` sites (for example [handler/error_registry.go:66](handler/error_registry.go#L66), [handler/json_handler.go:128](handler/json_handler.go#L128), [outbox/worker.go:34](outbox/worker.go#L34)). The sentinel-error → HTTP-status mapping at the handler boundary becomes a one-liner per type. A `go fix` modernizer converts these.

### 1.6 `new(expr)` (1.26)

`new(v)` now takes a value. [storage/azure.go:315](storage/azure.go#L315) `func to[T any](v T) *T` (4 uses) can be deleted. The change also helps optional `*T` JSON/DTO fields in downstreams.

### 1.7 Supporting library pieces for OO style

- **`reflect.Type.Fields()/Methods()`, `reflect.Value.Fields()/Methods()` iterators (1.26)**: cleaner reflection in [data/abstract_table_service.go](data/abstract_table_service.go) (`ExtractValue`) and anywhere REST auto-CRUD walks struct fields.
- **`hash/maphash.Hasher` / `ComparableHasher` (1.27)**: an interface contract for hashing and equality, so generic containers can take non-`comparable` keys polymorphically. Relevant only if `cache.LRU` ever needs struct/slice keys; no action now.

---

## 2. Standard library changes that affect keel

| Change | Ver | keel exposure | Action |
|---|---|---|---|
| `encoding/json` now runs on the **v2 engine** (same v1 semantics; different error *text*; much faster Unmarshal) | 1.27 | 82 files import it; no test asserts on json error text | None. Free speed-up. Opt out with `GOEXPERIMENT=nojsonv2` if a regression appears. |
| `encoding/json/v2` + `jsontext` (strict: rejects invalid UTF-8 and duplicate keys) | 1.27 | REST body decoding in `rest/` and `handler/json_handler.go` | Consider v2 `Unmarshal` for **inbound** REST bodies (duplicate-key rejection is a security win). Do it as a deliberate change, not during the bump. `go-json-experiment/json` (indirect) goes away over time. |
| New `uuid` package | 1.27 | keel uses no uuid lib; `google/uuid` is indirect only | Downstreams that import `google/uuid` can switch. |
| `strings.CutLast` / `bytes.CutLast` | 1.27 | [common/domain.go:23](common/domain.go#L23) | Optional cleanup. |
| `net/url`: `URL.Clone`, `Values.Clone` | 1.27 | 13 `url.Parse` files | Replace any hand-rolled URL copies. |
| `url.Parse` rejects extra colons in host (`http://h:80:80/`) | 1.26 | outbox webhooks, OAuth redirect URIs | Behavior tightening, and good. Watch partner-supplied webhook URLs. `GODEBUG=urlstrictcolons=0` escape hatch. |
| `ServeMux` trailing-slash redirect is now **307** instead of 301 | 1.26 | no test asserts 301 | None. |
| HTTP/1 `Response.Body.Close` drains unread body for connection reuse | 1.27 | outbox `http_dispatcher`, OAuth/provider clients | Positive. Verify no client is built per request (that would now cost more). |
| `http.Server.MaxHeaderValueCount` | 1.27 | keel HTTP server bootstrap | Candidate `--http_max_header_values` flag in `common/variables.go`. |
| HTTP/2 RFC 9218 client priority | 1.27 | none | None. |
| `httptest.NewTestServer` (in-memory net) + `testing/synctest.Sleep` | 1.27 | 47 httptest files; `clock/fake.go` | New tests can use `synctest` for timer-driven code (outbox, limiter, realtime, sweepers) instead of `clock.Fake`. Keep `clock.Clock` as the port. |
| `goroutineleak` profile GA (`/debug/pprof/goroutineleak`) | 1.27 | workers, realtime hub, outbox | Add to worker/server debug endpoints behind a flag. Use in tests of long-running workers. |
| Goroutine pprof labels in tracebacks | 1.27 | none (no `pprof.Do` usage) | Optional: label worker goroutines (`worker`, `partner_id`) for crash triage. **Never** put secrets in labels. |
| crypto: `rand` parameter now ignored in `rsa/ecdsa/ed25519` keygen and signing | 1.26 | no call site passes a non-`crypto/rand` reader | None. Use `testing/cryptotest.SetGlobalRandom` for deterministic tests. |
| `rsa` PKCS#1 v1.5 encryption deprecated; `ReverseProxy.Director` deprecated | 1.26 | not used | None. |
| TLS: hybrid PQ key exchange on by default; `crypto/mldsa`; legacy TLS GODEBUGs removed | 1.26/1.27 | 4 `crypto/tls` files, 5 `x509` files (PKCS#7, JWKS) | None required. ML-DSA JWKS/JWT signing is a future `crypto/` option. |
| `math/big.Int.Divide` with Trunc/Floor/Round/Ceil | 1.27 | [payment/money_math.go](payment/money_math.go) does manual banker's rounding | **Keep as is**: `Round` is not half-even. Use `Divide` only for trunc/floor/ceil paths. |
| `database/sql.ConvertAssign`, `driver.RowsColumnScanner` | 1.27 | 1 `database/sql` file (`data/scan_rows.go`); pgx elsewhere | None. |
| `log/slog.NewMultiHandler` | 1.26 | keel uses its own logger port, not slog | None. |
| `time` channels always synchronous (`asynctimerchan` removed) | 1.27 | 7 timer sites | None (already the default since 1.23). |
| `os/signal.NotifyContext` cancels with a cause | 1.26 | not used | Worker shutdown could log the signal via `context.Cause`. |

## 3. Runtime and compiler (free wins)

- **Green Tea GC is the default (1.26)**: 10–40% lower GC overhead. It is most noticeable in allocation-heavy REST/JSON paths and `AsMaps`.
- Size-specialized malloc (1.27): ~1% gain, +60 KB binary.
- Faster cgo (~30%); more slices allocated on the stack; heap base randomization.
- Closure symbol names are simpler, and identical closures may share code. **Never compare func pointers** (keel doesn't).

## 4. Tooling

- **`go fix` is now the modernizer suite** (1.26). New in 1.27: `embedlit`, `atomictypes`, `slicesbackward`, `unsafefuncs`. After bumping, run `go fix ./...` in keel and in each downstream, and review the diff. It covers `errors.AsType`, `new(expr)`, `embedlit`, `atomic.Int64` types, `wg.Go` (`waitgroupgo`), `min/max`, range-over-int and similar.
- **`go test` runs the `stdversion` vet check**: it catches library symbols newer than the `go` directive.
- **`go mod tidy` merges require blocks** (with `go ≥ 1.27`): keel's `go.mod` has three `require` blocks and will collapse to two (direct + indirect). Expect a noisy but harmless diff.
- `go doc pkg@version`, `go doc -ex`: useful for checking keel APIs from downstreams.
- **macOS 13+ is required** for the 1.27 toolchain.

---

## 5. Upgrade plan

A `go` directive in keel's `go.mod` is a **minimum for every consumer**. Bumping keel to `go 1.27.1` forces seo, daxoom, bdserp and bdsrest (all `go 1.25.3`) to 1.27 before they can take that keel release. Generic methods (1.1) *require* the 1.27 directive.

1. Install go1.27.1 locally and in CI and deploy images.
2. **keel**: set `go 1.27.1`, run `go mod tidy`, `go fix ./...` and `go test ./...`. Review the modernizer diff (it is style only).
3. **keel API additions** (separate commits): `QueryResult` generic accessors, delete `storage.to[T]`, switch to `errors.AsType`. These are additive, so no migration_guide entry is needed unless an exported symbol changes. If `content.Writers` wrappers are replaced (not recommended), record the old→new mapping in `migration_guide.json`.
4. Release keel and note the required Go version in the release notes and migration guide.
5. **Each downstream**: bump `go` and keel together, then run `go fix ./...` and tests. Moving from `common.As*(row[i])` to `QueryResult` accessors can happen gradually, one service at a time.

## 6. Risks

- **Low**: json error message text changed (clients parsing keel error strings would notice; keel wraps them in its own envelope). Stricter `url.Parse`. Flate output bytes differ (only matters if a test compares gzip/zip bytes).
- **Process**: the `go` directive forces the downstreams to move in lockstep. Do not ship keel on 1.27 until each downstream's toolchain is ready.
