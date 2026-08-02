# Operations

Day-2 guide for a running deployment: managing users, watching the stack, and routine upkeep.

## Managing users and connections

Postern has no self-serve signup. The operator creates users and their connections with the `postern` CLI, which ships inside the portal image:

```bash
# Add a user
docker compose exec portal postern user add "Alice" alice@example.com

# Give them a connection (creates a 24-hex-char path token + random password)
docker compose exec portal postern connection add alice@example.com "laptop"

# Inspect
docker compose exec portal postern user list
docker compose exec portal postern connection list --user-email alice@example.com

# Disable / enable / delete
docker compose exec portal postern connection disable <connection_id>
docker compose exec portal postern connection enable  <connection_id>
docker compose exec portal postern user disable alice@example.com
docker compose exec portal postern user delete  alice@example.com
```

Disabling is reversible: the database row (path token, password, label) stays, only the tunnel container is torn down, and `enable` brings the same tunnel back — the user's downloaded config keeps working. Deleting (`user delete`) removes the user and every connection they own; their tokens and configs stop working permanently.

Commands that change connection state (`connection add`/`enable`/`disable`, `user disable`/`delete`) trigger an immediate reconcile, so the corresponding container appears or disappears within a few seconds. Pure reads (`list`) and `user add` do not — a user with no connections needs no container.

Full command reference: [CLI](cli.md).

## The reconciler

The portal runs a background loop ([reconciler.py](https://github.com/bindreams/postern/blob/main/portal/src/postern/reconciler.py)) every `RECONCILE_INTERVAL_SECONDS` (default 60 s; see [configuration](../deployment/configuration.md)) that makes Docker match the database. Each pass it:

- creates a container for every enabled connection that lacks one, and removes orphans;
- restarts `ss-*` containers that have exited;
- recreates containers whose `local/shadowsocks-server` image ID differs from the current image (see [Updates](#updates));
- cleans up expired sessions and OTP codes from the database.

To trigger a pass immediately instead of waiting for the next poll:

```bash
docker compose exec portal postern reconcile
```

Under the hood, `postern reconcile` and every state-mutating CLI command create a `.reconcile-now` trigger file next to the database (`/data/.reconcile-now` in the default deployment); the loop notices it within a second, deletes it, and runs a pass. This is why CLI changes take effect in seconds rather than a minute.

## Logs

- **nginx** writes `access.log` and `error.log` to the host at `nginx/log/` in your checkout (bind mount).
- **portal**: `docker compose logs -f portal`.
- **`ss-*` tunnel containers** are deliberately logless — the reconciler creates them with Docker's `none` log driver, so no traffic metadata accumulates on disk. `docker logs` on them returns nothing by design.

## Restarts

```{warning}
Restarting the portal stops **all** tunnels. On shutdown the portal removes every `ss-*` container; the reconciler recreates them a few seconds after startup, but every user's connection is interrupted. Plan portal restarts (including `docker compose up -d --build`) accordingly.
```

Shutdown cleanup is best-effort: if the docker-proxy is unavailable while the portal is stopping, the `ss-*` containers survive into the next portal start. This is harmless — the reconciler adopts them on its next pass by their `postern.managed=true` + `postern.instance=<id>` labels.

### Instance identity

Every `ss-*` container the reconciler creates is stamped with a `postern.instance=<id>` label alongside `postern.managed=true`, and every reconciler listing (orphan sweep, shutdown wipe) filters on both. This matters if you ever run more than one Postern deployment against the same Docker daemon — for example a production stack plus a local e2e test run: without an instance-scoped filter, one deployment's reconciler would treat every *other* deployment's containers as orphans and delete them.

`<id>` needs no configuration in the normal case: `compose.yaml` sets `COMPOSE_PROJECT_NAME: ${COMPOSE_PROJECT_NAME:-}` on the portal service, which Docker Compose populates automatically from its own project name (the checkout's directory basename, or whatever `-p`/`COMPOSE_PROJECT_NAME` you used to bring the stack up). Set `INSTANCE_ID` explicitly only if that default could collide — e.g. two checkouts on one host whose directory basenames happen to sanitize to the same compose project name. If you do set it, **do not copy it** when cloning this stack to a second host or a second checkout; a copied `INSTANCE_ID` collision silently defeats the whole isolation mechanism (two deployments would treat each other's containers as their own). The reconciler logs both values at INFO at startup ("Resolved own instance id to ... (from INSTANCE_ID override; COMPOSE_PROJECT_NAME=...)") so a suspected collision can be confirmed by inspecting the logs — it's not a WARNING, because a deliberate override is indistinguishable, from inside one process, from a copied one.

If the portal cannot determine its own instance id at all (neither variable is set — e.g. the portal wasn't started via `docker compose`, or an old `compose.yaml` is in use), it fails safe: it skips *all* container creation, removal, and restart for that pass (session/OTP cleanup still runs), logs an error every pass to that effect, and every state-mutating `postern` CLI command prints a `WARNING` to that effect too.

```{important}
**Required after upgrading from a Postern version predating instance labeling.** Containers created before this feature existed carry `postern.managed=true` but no `postern.instance` label. The reconciler intentionally never auto-adopts them (auto-adoption of an unlabelled container is exactly as unsafe as sweeping a foreign deployment's container — there is no way to tell the two cases apart from the label alone). After your first upgrade past this point:

1. Run `docker compose up -d --build` as usual. Existing tunnels keep running untouched (the reconciler doesn't touch containers it doesn't recognize as its own). Because container names are deterministic (`ss-<path_token>`), the reconciler's create attempt for each already-tunneled connection hits a name conflict against the old, unlabelled container and backs off — it logs an error with `docker rm -f` guidance instead of creating a replacement. Nothing is duplicated; the connection keeps running on the OLD, unlabelled container in the meantime.
2. For each `ss-*` container that has `postern.managed=true` but no `postern.instance` label (`docker inspect --format '{{.Config.Labels}}' <name>` to check, or grep the reconciler's logs for "already in use by another container"), remove it manually: `docker rm -f <name>`. This interrupts that one tunnel briefly. The reconciler recreates it, correctly labelled, on its next pass (`docker ps --filter label=postern.managed=true --filter label=postern.instance=<your-instance-id>` to confirm).
3. For any **disabled** connection, or any connection removed via `postern user delete`, both the reconciler's own periodic check and the CLI itself (`connection disable` / `user delete` output) warn if that connection's container is still running and unlabelled — the reconciler will not stop it automatically, since ownership can't be proven. `user delete` cascades the connection row away entirely at the database level, so it checks each connection's container immediately, before the row is gone, rather than relying on the reconciler's periodic check (which needs a surviving row to attribute the warning to).
```

## Updates

```bash
git pull

# Rebuild the per-connection tunnel image. Compose does NOT build this one --
# the reconciler spawns it at runtime.
docker build -f shadowsocks/Dockerfile -t local/shadowsocks-server .

# Rebuild and restart the rest of the stack
docker compose up -d --build
```

The [shadowsocks image](https://github.com/bindreams/postern/blob/main/shadowsocks/Dockerfile) must be built from the repo root (it copies from `external/`); `docker build ./shadowsocks/` fails. After a rebuild, the reconciler detects the changed image ID and recreates each tunnel container — path tokens are unchanged, so client configs stay valid; each tunnel just drops briefly.

## Backup

State lives in named Docker volumes, declared in [compose.yaml](https://github.com/bindreams/postern/blob/main/compose.yaml):

```{list-table}
---
header-rows: 1
---
- - Volume
  - Contents
- - `postern-data`
  - The portal's SQLite database — users, connections (path tokens and passwords), sessions.
- - `postern-mta-data`
  - DKIM signing keys and rotation state (built-in MTA).
- - `postern-mta-queue`
  - The Postfix queue — in-flight mail, including deferred OTP emails awaiting retry.
```

The remaining volumes (`postern-letsencrypt`, `postern-edge`) are regenerated by the provisioner and need no backup.

```{note}
`./data/` in the checkout is **not** used — it is gitignored and nothing writes to it. The database exists only inside the `postern-data` volume.
```

To back up a volume to the current directory:

```bash
docker run --rm --network none -v postern-data:/data -v "$PWD:/backup" alpine:3 \
  tar czf /backup/postern-data.tgz -C /data .
```

Repeat with the other volume names. For a consistent snapshot of the SQLite database, stop the stack first with `docker compose down` (without `-v` — that flag deletes the volumes) and back up cold.

```{seealso}
[Renaming the deployment hostname](rename.md) — the domain-change runbook, which preserves all three volumes.
```

```{toctree}
---
maxdepth: 1
---
cli.md
rename.md
```
