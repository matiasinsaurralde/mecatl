# mecatl — Security Audit (first-principles zero-day hunt)

Branch: `claude/pensive-hopper-yrtoyd`
Started: 2026-09-16
Method: multi-agent, multi-wave, first-principles code analysis (no changelog/git-diff/internet).

## Threat model / win conditions
- Remote process crash (DoS) by an authenticated or unauthenticated user.
- Server-side arbitrary command execution (RCE) — remote, auth or unauth.
- Authentication / limit / validation bypass.
- Privilege escalation (lower-priv role → higher-priv; child → parent; project → operator tier).
- Sandbox escape (shell gate bypass, filesystem confinement escape, secret exfiltration).
- Deserialization / mass-assignment / injection.

## Attacker-facing surfaces (map)
- gRPC + HTTP/SSE server: `internal/adapter/server/{grpc,http,authn,cors,ownership,mcp_authorization,mcp_broker,worktree_selector,placement}.go`
- Auth/identity: `authn/oidc/*`, `internal/adapter/{clientauth,credentialstore}/*`, `mcp/oauthlogin/runtime.go`, `internal/adapter/resourceurl`, `internal/adapter/llmendpoint/url.go`
- Shell gate: `engine/governance/{shell,evaluator,substitution}.go`, `engine/internal/shellcompat/diagnostic.go`, `engine/adapter/fstools/shell.go`, `internal/app/escapeclassifier.go`
- Filesystem confinement / sandbox: `internal/adapter/osfs/osfs.go`, `engine/adapter/fstools/*`, `internal/adapter/forker/*`
- Permission model / escalation: `engine/governance/*`, `engine/agent/{dispatch,subagent,childask}.go`, `internal/app/{posture,guardrails}.go`
- Persistence / deserialization: `internal/adapter/server/mapper.go`, `internal/adapter/store/jsonlstore/*`, `internal/adapter/redisstore/*`, `engine/adapter/{sessnap,eventsource}/*`
- Egress: `engine/adapter/webfetch/*`, `engine/adapter/search/*`, MCP client
- Env/secrets: `internal/adapter/envscrub/*`, `internal/adapter/gitenv/*`
- Dependencies: `mvdan.cc/sh/v3` (shell parse), `goccy/go-yaml`, `bmatcuk/doublestar/v4`, `robfig/cron/v3`, `redis/go-redis/v9`, `golang-jwt/jwt/v5`, `coreos/go-oidc/v3`, `google.golang.org/{grpc,protobuf}`, `toolhive-core/redisconn`

## Approach registry (families)
- **F1 Shell-gate / command-exec bypass** — parser-vs-exec divergence, read-only misclassification.
- **F2 Filesystem sandbox escape** — path confinement, symlink, TOCTOU, read-roots, forker.
- **F3 Server ingress / auth bypass** — bearer/OIDC, interceptors, CORS, ownership, caller-identity, MCP-auth, worktree HMAC selector.
- **F4 Deserialization / crash / DoS** — proto mapper, jsonl/redis store, snapshot restore, event fold, unbounded alloc, nil deref.
- **F5 Privilege escalation / permission model** — scope precedence, floored-allow, subagent ask-review, audience, guardrails operator-tier, child-id spoof.
- **F6 Dependency interactions + SSRF + envscrub** — mvdan/sh vs /bin/sh, yaml, glob, redis, jwt; webfetch SSRF; secret-scrub gaps.

Status legend: 🔵 active · 🟡 stalled · 🔴 blocked · ✅ confirmed finding · ❌ ruled out

---

## Wave log

### Wave 1 — launched
- A→F1 shell gate; B→F2 fs/forker; C→F3 server auth; D→F4 deserialization/crash; E→F5 perm/escalation; F→F6 deps+SSRF+envscrub.

---

## Confirmed / candidate findings

_(none yet — pending Wave 1)_

## Ruled out / dead ends

### Root-agent independent recon (Wave 1, parallel to agents)
- **Redis key injection (cross-session R/W via session-id metacharacters)** — ❌ ruled out. `internal/adapter/redisstore/metadata_index.go`: all Redis keys are passed via `KEYS[]` (built Go-side by `sessionKey(id)` = `"mecatl:session:"+id` string concat, not a glob/pattern); owner scope is SHA-256-hashed (`metadataOwnerScope`), so no attacker text reaches an index key; `pageMetadataScript` uses `ZRANGEBYLEX` with a validated cursor member; and `decodeMetadataRows` re-checks `request.Owner.SameIdentity(row.Owner)` on `OwnershipEnforced` as row-level defense-in-depth. The `mecatl:session:` prefix (trailing colon) can't be crafted to collide with control keys (`mecatl:session-metadata:*`, `mecatl:events:`, `mecatl:tools:`). No injection.
- **jsonlstore filename path-traversal (client id / schedule name → file outside store dir)** — ❌ ruled out. `legacySafeName` (`jsonlstore.go:1326`) maps every rune outside `[a-zA-Z0-9._-]` to `_` and rewrites a leading `.` to `_`, so `/` and `..` cannot survive: `../../etc/passwd` → `_.._.._etc_passwd`. `safeFilePart` (schedules/fire ids) delegates to it. Traversal-proof.
  - ⚠️ Minor residual (LOW, jsonl backend only): `legacySafeName` is LOSSY/non-injective — distinct schedule names collide to one filename (`a/b` and `a_b` → `a_b`). If schedule NAME is client-controlled and not owner-namespaced on disk, a name-collision could overwrite/hijack another schedule's file. Needs: (1) is schedule name client-controlled on the wire? (2) is the on-disk file owner-scoped? → handed to F4/wave-2.

### Root-agent recon: F7 mecatequi CI patch-as-data (`.github/actions/mecatequi-publish/publish.sh`) — well-defended (tested)
- The publish job applies the agent's diff as DATA (`git apply --3way --index`), env-fed inputs (no argv splice), template substitution literal/single-pass/display-only, and a **protected-path gate** rejecting patches touching `.github/`, `.gitattributes`, `.git/`, `Makefile`, `Taskfile.yaml` via `git apply --numstat -z` (correctly using `-z` to defeat the C-quoting path-bypass).
- **Tested bypass attempt (symlink-through-directory):** a patch creating `link -> .github` then writing `link/evil.yml` makes numstat report `link/evil.yml` — the protected-path gate **PASSES it (does not block)**. BUT `git apply --3way --index` refuses: `error: affected file 'link/evil.yml' is beyond a symbolic link` (git 2.43 symlink hardening). So the two layers hold on modern git. ⚠️ Residual (defense-in-depth): the gate itself IS bypassable; the sole backstop is git's symlink check — an old/patched git (<2.14) or another numstat-vs-apply path divergence would fail the gate open. Handed to F7/wave-2 as low-priority.
- Numstat-parse-fail ⇒ gate empties ⇒ passes, but `--3way` shares the same diff parser, so an unparseable-by-numstat patch is also unappliable — no divergence there. Blast radius further bounded by: agent job holds NO GitHub token; envscrub scrubs provider keys from the shell; PR still needs human merge.

### Open questions feeding the families
- **Is the session ID client-controlled on the CreateSession wire?** `server.WithSessionID` exists (used by scheduler `sched--` path, `session_id_override_test.go`) but appears to be an internal Go option. If a wire field maps to it, several id-based invariants (child-id prefix guard `isDelegationChildSessionID`, owner scoping, redis/jsonl keying) get attacker-controlled input. → F3/F4 must confirm.
- **Owner-principal provenance (crux for F3 + scheduler escalation).** `scheduler_fire.go` runs each fire under `schedulerOwnerContext` = `session.WithPrincipal(ctx, sched.Spec.Owner)` and stamps the fire session owner = `fireSessionOwner(sched.Spec.Owner)`. So the fire executes with the **schedule's captured owner identity**. If a low-priv caller can set/spoof `sched.Spec.Owner` at CreateSchedule (client field rather than authenticated principal), a fire escalates to that identity. Same question governs `CreateSession` owner and every `Owner.SameIdentity` ownership check. → **F3 must trace: is `Principal` derived from the verified auth token/OIDC claims, or from a client-supplied request field?** This is the single highest-leverage crux.

### Root-agent recon: front-door auth (`internal/adapter/server/authn.go`) — SOLID; resolves the owner-provenance crux
- **Owner spoofing via a client field is CLOSED.** The `Principal` on the handler context comes ONLY from the verified validator output (`UnaryInterceptor`/`StreamInterceptor` → `authGRPC` → `session.WithPrincipal(ctx, p)` where `p` is `Validator.Validate(bearer)`), never a request field. `admissiblePrincipal` re-checks at the edge: rejects nil/empty iss|sub, `GrantTypeSystem`, the internal issuer (`syscaller.Issuer`), invalid grant enum, and NUL in identity (owner-key-collision defense). Constant-time token compare (`subtle.ConstantTimeCompare`). Duplicate `authorization` metadata rejected (no first/last-value ambiguity). So the scheduler's captured `Spec.Owner` = the authenticated caller; a low-priv caller cannot mint a fire as someone else.
- **Residual risk re-aimed for F3/F6 (NOT owner-spoofing):**
  1. **Validator soundness** — the real JWT/OIDC checks are DELEGATED to `toolhive-core/authn` (injected `PrincipalValidator`). If it skips audience/issuer/exp/signature or is alg-confusable, everything downstream falls. → F6 must audit that dep + `authn/oidc`.
  2. **Authorization (not authentication) coverage** — is the per-session `Owner.SameIdentity` ownership check applied on EVERY mutating/read RPC (StartRunContent, Approve/Deny, ListCommands/Worktrees, Clear/Fork, schedule CRUD, transcript/event read)? A single unguarded RPC = cross-tenant access with a valid low-priv token. → F3's core.
  3. **Identity-OFF default** — `Validator==nil` ⇒ `p==nil` everywhere ⇒ all sessions ownerless (documented loopback posture). The dangerous middle config is **static-token-only** (shared credential, zero subjects): every holder co-owns all sessions. Confirm no RPC assumes identity is on.

### Root-agent recon: scheduler fire path (`internal/app/scheduler_fire.go`) — mostly well-defended
- Fire runs read-leaning (plan mode) unless `Spec.Mutating`; applies subagent-grade turn/tool caps; owner-scoped ctx; ownerless schedule keeps system ctx and *fails closed* at caller-owned boundaries. Carried context is FENCED untrusted (not seeded history). Watchdog cancel → StopTimeout. No obvious elevation *given* a trustworthy `Spec.Owner`. The whole security of this path reduces to the owner-provenance crux above.
