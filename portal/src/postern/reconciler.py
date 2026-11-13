"""Container reconciliation loop.

Ensures Docker containers match the desired state in the database.
Runs as a background asyncio task in the FastAPI lifespan.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import re
import threading
from dataclasses import dataclass

import docker
import docker.errors
import docker.types
from docker.models.containers import Container
from docker.models.images import Image
from docker.models.networks import Network

from postern import db, reconcile_wait
from postern.models import Connection
from postern.settings import Settings
from postern.ss_config import server_config_b64

logger = logging.getLogger(__name__)

MANAGED_LABEL = "postern.managed"
MANAGED_VALUE = "true"
INSTANCE_LABEL = "postern.instance"

# The only instance ids the docker-proxy accepts (it pastes the id into a daemon filter). docker-proxy/policy.lua and
# scripts/verify-deploy.py validate the same way; tests/test_docker_proxy_policy.py compares all three on edge cases.
_ASCII_WHITESPACE = " \t\n\v\f\r"
INSTANCE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")

# What every tunnel container is created with. The docker-proxy's allow-list (docker-proxy/policy.lua) repeats these
# three and refuses a create body that differs; tests/test_compose_docker_proxy.py pins the copies equal.
# 512 MiB and 1024 pids leave generous headroom over the measured footprint (pids count threads and scale with CPU
# count). The second tmpfs is galoshes' extraction directory: it must be writable and executable while the rest of the
# root filesystem is read-only.
SS_MEMORY_BYTES = 536870912
SS_PIDS_LIMIT = 1024
SS_TMPFS = {"/tmp": "", "/home/nonroot/.cache": "exec"}

# Set by request_reconcile_shutdown() (called from app.py BEFORE cancelling the
# reconciliation loop's task) to ask an in-flight pass to stop between container
# operations instead of finishing its full desired-connections loop. This bounds
# the COMMON shutdown case; it is not itself a correctness guarantee --
# wait_for_inflight_reconcile() (below, unbounded) is the actual guarantee that
# cleanup_all_containers never races a straggler create/remove, regardless of
# whether a given pass happens to notice this flag in time.
_shutdown_requested = threading.Event()


def request_reconcile_shutdown() -> None:
    """Ask any in-flight reconcile pass to wind down between operations.
    Call BEFORE cancelling the reconciliation loop's task."""
    _shutdown_requested.set()


def _owned_by_instance(labels: dict[str, str], instance_id: str) -> bool:
    """The MANAGED_LABEL+INSTANCE_LABEL conjunction, factored out so
    `_list_managed_containers`'s Docker `filters=` kwarg (which has to
    express this as an API filter, not a predicate) and
    `_log_name_conflict`'s own-instance-retry check test the identical
    condition in Python.
    """
    return labels.get(MANAGED_LABEL) == MANAGED_VALUE and labels.get(INSTANCE_LABEL) == instance_id


# Whether the resolved instance id + its provenance (override vs
# COMPOSE_PROJECT_NAME) has already been logged once this process. Only set
# once a pass actually resolves identity -- a failed pass leaves it False so
# the log still fires on the first pass that succeeds, however delayed.
_startup_identity_logged = False

# Dedicated single-worker executor for reconcile passes (kept separate from
# asyncio's default executor so this module's threading behavior is self-
# contained and doesn't share a pool with unrelated to_thread callers).
#
# Deliberately module-level and never explicitly .shutdown() -- it needs to
# survive across multiple reconciliation_loop()/lifespan cycles within one
# process (every PosternApp instance in the test suite shares this same
# module). Calling .shutdown() at the end of one lifespan would make the SAME
# executor permanently unusable for any later one in the same process
# (further .submit() calls raise RuntimeError). concurrent.futures already
# registers an atexit hook that joins any live worker threads at actual
# interpreter exit, so nothing here can leave PID 1 (or a pytest run)
# hanging on its own.
_executor = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix="postern-reconciler")

# The RAW concurrent.futures.Future (NOT an asyncio-wrapped one) backing the
# currently in-flight reconcile pass, if any. A stale reference to an
# already-completed future is harmless (wait_for_inflight_reconcile checks
# .done()); it's simply overwritten by the next pass, so nothing here ever
# needs to clear it.
_inflight_reconcile_future: concurrent.futures.Future | None = None


async def wait_for_inflight_reconcile() -> None:
    """Block until any in-flight reconcile pass's container work has
    GENUINELY finished, not just until a cancelled Task that was awaiting it
    has unwound. `asyncio.to_thread`/`run_in_executor` cancellation only
    detaches the awaiting coroutine from the underlying thread -- it does
    NOT stop that thread. Called once, from app.py's shutdown sequence,
    between cancelling the reconciler task and calling
    cleanup_all_containers, so the sweep can never run concurrently with a
    straggler create (which would also use-after-close the DockerClient
    reconcile()'s own finally has since closed). No arbitrary timeout:
    `asyncio.wrap_future` on the tracked raw future blocks until that
    future is genuinely done, however long that takes.

    Must be called from an uncancelled context: `asyncio.shield` protects
    the raw future itself, not this await, so a cancellation here would
    abandon the wait without the guarantee actually breaking.
    """
    future = _inflight_reconcile_future
    if future is None:
        return
    if future.done():
        # Already finished by the time we got here (e.g. no pass was ever
        # in flight, or it wrapped up on its own) -- still surface a
        # failure if there was one, the same as the live-wait branch below
        # would, rather than silently discarding it.
        exc = future.exception()
        if exc is not None:
            logger.error("In-flight reconcile pass failed", exc_info=exc)
        return
    try:
        await asyncio.shield(asyncio.wrap_future(future))
    except Exception:
        # _reconcile_pass logs its own EXPECTED failure modes already (name
        # conflicts, restart failures, etc. -- see _create_container_logged
        # and friends). Anything that reaches here is something that
        # escaped that handling entirely; it can no longer be attributed to
        # whatever originally dispatched this pass (already cancelled), so
        # log it here rather than silently discarding it.
        logger.exception("In-flight reconcile pass failed")


def _container_name(conn: Connection) -> str:
    return f"ss-{conn.path_token}"


def _container_network_ids(container: Container) -> set[str]:
    """IDs of the Docker networks `container` is currently attached to, read
    from the same `.attrs` inspect payload the image-change check already
    has -- no extra Docker API call.

    Deliberately IDs, not the `NetworkSettings.Networks` dict KEYS (which
    docker-py's `containers.run(network=<name>)` sets to the network's
    canonical name regardless of what was passed at create time -- a value
    that happens to be a network ID or ID prefix would then never match its
    own canonical name, and the container would be recreated every pass,
    forever). A network deleted and recreated under the same name also gets
    a new ID, so comparing IDs (not names) is also what makes a stale
    survivor from that case get recreated instead of silently kept.

    A `created`-status container (its `containers.run()` create succeeded
    but start() has not, or hasn't yet) has a REAL, empty `NetworkID` for
    its endpoint until start() actually runs -- returning the empty set for
    that case is correct, but the caller must NOT treat "no IDs at all" the
    same as "attached to a different network": that container hasn't
    resolved its endpoint yet, not proven to be on the wrong one.
    """
    attrs = container.attrs or {}
    networks = ((attrs.get("NetworkSettings") or {}).get("Networks")) or {}
    return {info["NetworkID"] for info in networks.values() if info and info.get("NetworkID")}


def _recreate_reasons(container: Container, current_image: Image | None, target_network: Network | None) -> list[str]:
    """The reasons `container` no longer matches desired state and must be
    recreated: its recorded image differs from `current_image`, and/or it
    isn't attached to `target_network`. Returns a LIST, not a bool, so the
    caller can report every reason at once and so a third staleness axis
    (added later) is one more `if` here, not a new branch at each call site.

    `current_image`/`target_network` are `None` when that lookup itself
    failed this pass (see `_reconcile_once`) -- the corresponding axis is
    then skipped entirely, never treated as a mismatch: recreating on the
    strength of an unresolved desired state risks destroying a working
    container for nothing.
    """
    reasons = []
    attrs = container.attrs or {}
    # container.attrs["Image"] is the image ID stored on the container at create
    # time. Cheaper than container.image.id (which does an images.get() lookup
    # and 404s when the old image has been garbage-collected after rebuild).
    if current_image is not None and attrs.get("Image") != current_image.id:
        reasons.append("image")

    if target_network is not None:
        container_network_ids = _container_network_ids(container)
        if container_network_ids:
            # Normal case: compare resolved network IDENTITY (handles a
            # network deleted and recreated under the same name -- see
            # _container_network_ids' docstring).
            if target_network.id not in container_network_ids:
                reasons.append("network")
        elif container.status == "created":
            # Not yet started: no NetworkID to compare (see
            # _container_network_ids' docstring for why that's real, not a
            # bug), so fall back to the CONFIGURED network NAME -- Docker's
            # own canonical name (`target_network.name`), not
            # `settings.shadowsocks_network` verbatim: that setting may
            # itself be a network ID, and comparing the raw string here
            # would reintroduce the exact ID-vs-name mismatch the ID
            # comparison above exists to avoid. A container correctly
            # configured for the target network whose start() just keeps
            # failing must not be torn down every pass (the restart loop
            # above already owns retrying it) -- but one whose configured
            # network no longer matches, e.g. it was deleted while the
            # container sat unstarted, is a proven mismatch and must still
            # self-heal rather than being wedged forever.
            if target_network.name not in _container_network_names(container):
                reasons.append("network")
        else:
            # Running (or exited) with zero resolved endpoints -- e.g.
            # `docker network disconnect -f` against a live container -- is
            # a real, proven mismatch, not an unresolved one.
            reasons.append("network")

    return reasons


def _container_network_names(container: Container) -> set[str]:
    """CONFIGURED network names -- the `NetworkSettings.Networks` dict KEYS,
    set at create time and unaffected by whether the network still exists.
    Fallback `_recreate_reasons` uses for a `created`-status container; see
    its comments for why.
    """
    attrs = container.attrs or {}
    networks = ((attrs.get("NetworkSettings") or {}).get("Networks")) or {}
    return set(networks)


def _get_docker_client() -> docker.DockerClient:
    return docker.DockerClient.from_env()


def _ascii_stripped(value: str) -> str:
    """Stripped of ASCII whitespace only, as the docker-proxy does (Python's own `strip()` also drops Unicode spaces,
    which would let the portal accept an id the proxy refuses)."""
    return value.strip(_ASCII_WHITESPACE)


def configured_instance_id(settings: Settings) -> str:
    """The id `resolve_instance_id` validates: the INSTANCE_ID override, else the compose project name, else ""."""
    return _ascii_stripped(settings.instance_id) or _ascii_stripped(settings.compose_project_name)


def instance_id_fault(settings: Settings) -> str:
    """Why `resolve_instance_id` returned None, naming the offending value and the pattern. For the callers that
    report it; resolving itself logs nothing, so a fault is reported once per caller."""
    chosen = configured_instance_id(settings)
    if chosen:
        return f"{chosen!r} is not a valid id: it must match {INSTANCE_ID_PATTERN.pattern}"
    return "neither INSTANCE_ID nor COMPOSE_PROJECT_NAME is set"


def resolve_instance_id(settings: Settings) -> str | None:
    """Resolve this portal's instance id from configuration alone -- no live
    Docker API call.

    Multiple Postern deployments (production, an e2e run, ...) can share one
    Docker daemon. An explicit INSTANCE_ID override always wins (the escape
    hatch for a compose-project-name collision); otherwise use
    compose_project_name, which `compose.yaml` populates automatically via
    Docker Compose's own `${COMPOSE_PROJECT_NAME}` interpolation. Both
    inputs come from `Settings`, constructed once at process startup, so
    this returns the identical value for the entire life of the process.

    Returns None when NEITHER is set -- the portal wasn't started via an
    up-to-date `docker compose` invocation at all -- or when the id in use
    does not match INSTANCE_ID_PATTERN (the docker-proxy would refuse every
    request carrying it; an invalid override does not fall back to the
    project name, matching the proxy). Callers must treat None as "unknown"
    and skip every destructive container operation, reporting `instance_id_fault`.
    """
    chosen = configured_instance_id(settings)
    return chosen if INSTANCE_ID_PATTERN.fullmatch(chosen) else None


def _log_resolved_identity_once(settings: Settings, instance_id: str) -> None:
    """Log the resolved instance id and its provenance exactly once per
    process.

    An INSTANCE_ID override differing from compose_project_name is NOT by
    itself a fault to warn about: it's also the shape of the one documented
    legitimate use (two checkouts whose directory basenames sanitize to the
    same compose project name, disambiguated with an explicit override) --
    that case is indistinguishable, from inside this one process, from a
    copied .env accidentally colliding with a different deployment's id.
    Log both values at INFO so an operator debugging a suspected collision
    has them on hand, without a WARNING that would fire on every correctly
    configured override deployment and teach operators to ignore it.
    """
    override = _ascii_stripped(settings.instance_id)
    if not override:
        logger.info("Resolved own instance id to %r (from COMPOSE_PROJECT_NAME)", instance_id)
        return
    derived = _ascii_stripped(settings.compose_project_name)
    if derived and derived != instance_id:
        logger.info(
            "Resolved own instance id to %r (from INSTANCE_ID override; COMPOSE_PROJECT_NAME=%r). "
            "INSTANCE_ID must be unique per Postern deployment sharing a Docker daemon -- if this "
            "value was copied from another deployment's .env rather than chosen deliberately, "
            "both deployments will treat each other's containers as their own.",
            instance_id,
            derived,
        )
    else:
        logger.info("Resolved own instance id to %r (from INSTANCE_ID override)", instance_id)


def _list_managed_containers(client: docker.DockerClient, instance_id: str) -> dict[str, Container]:
    """Return name -> container for containers managed by *this* portal instance.

    The instance label is required, not optional: a listing scoped only to
    MANAGED_LABEL would match containers from every Postern deployment
    sharing this daemon. Containers predating this label (or belonging to a
    different instance) intentionally match no filter here and are never
    adopted by a bare listing -- see `_log_name_conflict` for how a
    create-time collision with one is handled (logged, never auto-removed
    unless it's already labelled for this exact instance).

    `ignore_removed=True`: docker-py's list() inspects each matched id
    individually after the initial listing call, and by default re-raises
    `NotFound` if one vanished in between (a benign race, e.g. this
    instance's own in-flight pass removing a container concurrently with
    this call) as a hard failure of the WHOLE listing. That would abort an
    entire reconcile pass -- or worse, `cleanup_all_containers`'s shutdown
    sweep -- over one container that simply isn't there anymore.
    """
    containers = client.containers.list(
        all=True,
        ignore_removed=True,
        filters={"label": [f"{MANAGED_LABEL}={MANAGED_VALUE}", f"{INSTANCE_LABEL}={instance_id}"]},
    )
    return {c.name: c for c in containers}


@dataclass(frozen=True)
class ContainerSummary:
    """What a container list payload says about one container. `state` is the string `Container.status` would be."""
    name: str
    labels: dict[str, str]
    state: str


def _read_container_summaries(client: docker.DockerClient, filters: dict) -> list[ContainerSummary]:
    """List containers matching `filters` and return what the LIST payload carries (name, labels, state).

    Private on purpose: the docker-proxy allows exactly two list shapes (this deployment's label pair, and one
    anchored `ss-<token>` name), so the public surface is one function per shape, not this one.

    A list payload has no `Env`, whereas `containers.get()` / docker-py's `containers.list()` inspect each container
    and return its whole config; the proxy denies an inspect of anything that does not carry this deployment's labels.
    """
    summaries = []
    for entry in client.api.containers(all=True, filters=filters):
        names = entry.get("Names") or [""]
        summaries.append(
            ContainerSummary(
                name=names[0].removeprefix("/"),
                labels=dict(entry.get("Labels") or {}),
                state=entry.get("State") or "",
            )
        )
    return summaries


def find_container_summary_by_name(client: docker.DockerClient, name: str) -> ContainerSummary | None:
    """Read a container the portal may not own, by its exact `ss-<24 hex>` name; None if there is none.

    This is the only way to read such a container. The proxy allows this one list shape (an anchored name filter);
    any other name is refused. The daemon's name filter is an unanchored regex, so the request anchors it and the
    result is checked for an exact match as well."""
    for summary in _read_container_summaries(client, {"name": [f"^/{name}$"]}):
        if summary.name == name:
            return summary
    return None


def _image_exists(client: docker.DockerClient, image_name: str) -> bool:
    try:
        client.images.get(image_name)
        return True
    except docker.errors.ImageNotFound:
        return False


def _create_container(client: docker.DockerClient, conn: Connection, settings: Settings, instance_id: str) -> None:
    """Create and start an SS container for the given connection."""
    name = _container_name(conn)
    config_b64 = server_config_b64(conn, settings.domain)

    logger.info("Creating container %s for connection %s", name, conn.id)

    client.containers.run(
        image=settings.shadowsocks_image,
        name=name,
        detach=True,
        init=True,
        environment={"SS_CONFIG": config_b64},
        labels={MANAGED_LABEL: MANAGED_VALUE, INSTANCE_LABEL: instance_id},
        log_config=docker.types.LogConfig(type="none"),
        restart_policy={"Name": "unless-stopped"},
        tmpfs=SS_TMPFS,
        network=settings.shadowsocks_network,
        cap_drop=["ALL"],
        security_opt=["no-new-privileges:true"],
        read_only=True,
        mem_limit=SS_MEMORY_BYTES,
        pids_limit=SS_PIDS_LIMIT,
    )


def _log_name_conflict(client: docker.DockerClient, name: str, instance_id: str) -> None:
    """A 409 on create means a container already occupies this connection's
    deterministic name (`ss-<path_token>`) but wasn't in this instance's
    managed set. This NEVER removes anything unless the squatter is
    provably this instance's own:

    - If it's already labelled for THIS instance, a prior removal (orphan
      sweep or image-upgrade recreate) must have silently failed, leaving
      it behind -- no manual action needed, the next pass's remove-then-
      create simply retries.
    - If it can't even be read, ownership is unconfirmed, not
      disproven -- that gets its own honest disposition, not the
      confirmed-foreign message.
    - Otherwise it's most likely a container this exact deployment created
      before the instance label existed, but it could also belong to a
      different Postern deployment (a cloned database makes `path_token`s
      collide by construction). Log the squatter's current labels so an
      operator can attribute it and remove it manually once confirmed
      safe; the next pass then creates it correctly.

    The squatter is read from a name-filtered list payload (labels only, never
    its `Env`: see `find_container_summary_by_name`). The 409-then-read sequence is
    inherently racy: the squatter can be removed between containers.run()
    raising 409 and this read -- most plausibly by an operator following this
    very function's own `docker rm -f` remediation advice, or a `--rm`
    auto-removal. An empty read is benign and self-healing (the name is free
    again; the next pass creates the container) -- it must not log the same
    "docker-proxy issue?" ERROR a genuine read failure gets, which would read
    as "the remediation didn't work" at the exact moment it did.
    """
    try:
        squatter = find_container_summary_by_name(client, name)
    except Exception:
        logger.error(
            "Container name %s is already in use, but the conflicting container could not be "
            "inspected to determine ownership (docker-proxy issue?); skipping remediation "
            "guidance this pass -- the next pass will retry",
            name,
            exc_info=True,
        )
        return
    if squatter is None:
        logger.info(
            "Container name %s conflict resolved itself (the squatter was removed between the "
            "create attempt and this check); the next reconcile pass will create it",
            name,
        )
        return
    squatter_labels = squatter.labels

    if _owned_by_instance(squatter_labels, instance_id):
        logger.warning(
            "Container %s is already in use by this instance's own container (a prior "
            "removal likely failed silently); the next reconcile pass will retry",
            name,
        )
        return

    logger.error(
        "Container name %s is already in use by another container (labels: %r) that this "
        "instance does not manage. The reconciler never removes a name-conflicting container "
        "automatically -- ownership can't be proven without risking a live container from a "
        "different Postern deployment. If you're sure it's safe (e.g. it predates the "
        "postern.instance label, or is a leftover from a rename), remove it manually "
        "(`docker rm -f %s`); the next reconcile pass will then create it correctly.",
        name,
        squatter_labels,
        name,
    )


def _create_container_logged(
    client: docker.DockerClient, conn: Connection, settings: Settings, instance_id: str
) -> None:
    """Create conn's container, converting every failure into a logged
    disposition instead of propagating. A name conflict (409) gets the
    dedicated, non-destructive handling in `_log_name_conflict`; anything
    else gets the ordinary generic disposition."""
    name = _container_name(conn)
    try:
        _create_container(client, conn, settings, instance_id)
    except docker.errors.APIError as e:
        if e.status_code == 409:
            _log_name_conflict(client, name, instance_id)
        else:
            logger.exception("Failed to create container %s", name)
    except Exception:
        logger.exception("Failed to create container %s", name)


def _remove_container(container: Container) -> bool:
    """Stop and remove a container. Returns True iff the container no
    longer exists afterward (including if it was already gone).
    Best-effort: failures are logged, never raised."""
    logger.info("Removing container %s", container.name)
    try:
        container.stop(timeout=10)
    except Exception:
        logger.debug("Failed to stop container %s before removal", container.name, exc_info=True)
    try:
        container.remove(force=True)
        return True
    except docker.errors.NotFound:
        return True
    except Exception:
        logger.exception("Failed to remove container %s", container.name)
        return False


def _reconcile_once(
    client: docker.DockerClient,
    connections: list[Connection],
    settings: Settings,
    instance_id: str,
) -> None:
    """Single reconciliation pass. Called from the async loop in a thread."""
    managed = _list_managed_containers(client, instance_id)
    desired_names = {_container_name(c) for c in connections}

    # Create missing containers ----------------------------------------------------------------------------------------
    for conn in connections:
        if _shutdown_requested.is_set():
            logger.info("Shutdown requested; stopping reconcile pass early")
            return
        name = _container_name(conn)
        if name not in managed:
            _create_container_logged(client, conn, settings, instance_id)

    # Remove orphan containers -----------------------------------------------------------------------------------------
    for name, container in managed.items():
        if _shutdown_requested.is_set():
            logger.info("Shutdown requested; stopping reconcile pass early")
            return
        if name not in desired_names:
            _remove_container(container)

    # Restart exited/never-started containers --------------------------------------------------------------------------
    # "created" happens when containers.run()'s create succeeded but its start() call
    # failed (docker-py's create-then-start has no rollback); container.start() works
    # identically for both statuses. Re-fetch after creates/removes above.
    managed = _list_managed_containers(client, instance_id)
    for name, container in managed.items():
        if _shutdown_requested.is_set():
            logger.info("Shutdown requested; stopping reconcile pass early")
            return
        if name in desired_names and container.status in ("exited", "created"):
            logger.info("Starting container %s (status=%s)", name, container.status)
            try:
                container.start()
            except Exception:
                logger.exception("Failed to start container %s", name)

    # Check for image/network updates ----------------------------------------------------------------------------------
    # Re-fetch again: container.start() above does not update the already-fetched
    # `managed` containers' .attrs in place, and its network attach isn't visible
    # until start() runs (see _container_network_ids' docstring) -- reading the
    # pre-start snapshot here would wrongly recreate a container just successfully
    # started.
    managed = _list_managed_containers(client, instance_id)
    # Broad except on both lookups: docker.errors.ImageNotFound / a
    # docker-proxy hiccup (generic APIError) / an empty SHADOWSOCKS_NETWORK
    # (docker.errors.NullResource, a ValueError, not an APIError) must all
    # degrade the same way -- log and leave the axis None, never raise out
    # of _reconcile_once.
    try:
        current_image = client.images.get(settings.shadowsocks_image)
    except Exception:
        logger.error(
            "Could not resolve image '%s'; skipping recreate checks this pass",
            settings.shadowsocks_image,
            exc_info=True,
        )
        current_image = None

    try:
        target_network = client.networks.get(settings.shadowsocks_network)
    except Exception:
        logger.error(
            "Could not resolve network '%s'; skipping recreate checks this pass",
            settings.shadowsocks_network,
            exc_info=True,
        )
        target_network = None

    if current_image is None or target_network is None:
        # A replacement is always built from settings.shadowsocks_image +
        # settings.shadowsocks_network (see _create_container), never from
        # these resolved objects -- so if EITHER failed to resolve, a
        # remove-then-create on the strength of the OTHER axis alone risks
        # destroying a working container and then failing to replace it,
        # using the exact resource that just failed to resolve. Skip the
        # whole recreate-and-destroy step for every container this pass
        # rather than treating the axes as independent past this point; the
        # next pass retries both lookups fresh.
        return

    for name, container in managed.items():
        if _shutdown_requested.is_set():
            logger.info("Shutdown requested; stopping reconcile pass early")
            return
        if name not in desired_names:
            continue

        reasons = _recreate_reasons(container, current_image, target_network)
        if not reasons:
            continue
        stale = " and ".join(reasons)
        logger.info("%s changed for %s, recreating", stale.capitalize(), name)

        conn = next(c for c in connections if _container_name(c) == name)
        if _remove_container(container):
            _create_container_logged(client, conn, settings, instance_id)
        else:
            # Recreating now would just 409 against the container we failed to
            # remove -- _log_name_conflict would then log "a prior removal
            # likely failed silently... will retry" every pass forever with no
            # escalation, while the tunnel keeps serving the OLD config
            # indefinitely (exactly what this check exists to prevent). Escalate
            # here instead, once, at the point we actually know removal failed.
            logger.error(
                "Could not remove %s to recreate it on the new %s; it still serves the OLD "
                "%s and will be retried next pass",
                name,
                stale,
                stale,
            )


def _reconcile_pass(
    client: docker.DockerClient,
    connections: list[Connection],
    settings: Settings,
    instance_id: str,
) -> None:
    """Everything reconcile() dispatches to the executor thread: the
    ordinary pass, and closing `client` -- owned here, not by
    reconcile()'s own coroutine, so a cancelled awaiting task can never
    race a close() against Docker calls this same thread still has in
    flight.
    """
    try:
        _reconcile_once(client, connections, settings, instance_id)
    finally:
        client.close()


async def reconcile(database_path: str, settings: Settings) -> None:
    """Run a single reconciliation pass."""
    global _startup_identity_logged, _inflight_reconcile_future
    async with db.get_connection(database_path) as database:
        try:
            instance_id = resolve_instance_id(settings)
            if instance_id is not None and not _startup_identity_logged:
                _log_resolved_identity_once(settings, instance_id)
                _startup_identity_logged = True

            client = _get_docker_client()
            try:
                if not _image_exists(client, settings.shadowsocks_image):
                    logger.error(
                        "Image '%s' not found. Build it from the repo root with: "
                        'GIT_REVISION="$(scripts/verify-deploy.py --print-revision)" && export GIT_REVISION && '
                        'docker build --pull -f shadowsocks/Dockerfile --build-arg GIT_REVISION="$GIT_REVISION" -t %s .',
                        settings.shadowsocks_image,
                        settings.shadowsocks_image,
                    )
                elif instance_id is not None:
                    connections = [c for c in await db.list_connections(database) if c.enabled]
                    future = _executor.submit(_reconcile_pass, client, connections, settings, instance_id)
                    _inflight_reconcile_future = future
                    client = None  # ownership transferred to _reconcile_pass; the finally below must not close it
                    await asyncio.shield(asyncio.wrap_future(future))
                else:
                    logger.error(
                        "Skipping container reconciliation this pass (session/OTP cleanup still runs): "
                        "could not determine the instance id (%s). Fix INSTANCE_ID, or COMPOSE_PROJECT_NAME "
                        "when INSTANCE_ID is empty.",
                        instance_id_fault(settings),
                    )
            finally:
                if client is not None:
                    client.close()
        finally:
            await db.cleanup_expired(database)


async def reconciliation_loop(database_path: str, settings: Settings) -> None:
    """Main reconciliation loop. Runs until cancelled."""
    _shutdown_requested.clear()
    trigger_path = reconcile_wait.data_dir(database_path) / ".reconcile-now"

    try:
        while True:
            reconcile_wait.sweep_orphan_waiters(database_path)
            waiters = reconcile_wait.snapshot_waiters(database_path)
            # Fail-safe default: only the line right after a successful `await
            # reconcile(...)` proves a pass actually completed. Defaulting to True
            # and clearing it only in specific except clauses would silently notify
            # "ok" for any exception type neither clause names (e.g. a bare
            # BaseException) -- the opposite of what this handshake exists for.
            passed = False
            try:
                await reconcile(database_path, settings)
                passed = True
            except asyncio.CancelledError:
                # Shutdown: app.py cancels this task and then removes every ss-*
                # container. A waiter told "ok" here would believe its tunnels had
                # just been reconciled, seconds before they are all deleted.
                raise
            except Exception:
                logger.exception("Reconciliation failed")
            finally:
                # Notify even on failure: a deploy blocked on this must get a
                # verdict, not a hang.
                reconcile_wait.notify_waiters(waiters, ok=passed)

            # Wait for interval or trigger file
            for _ in range(settings.reconcile_interval_seconds):
                if trigger_path.exists():
                    try:
                        trigger_path.unlink()
                    except OSError:
                        pass
                    break
                await asyncio.sleep(1)
    finally:
        # The loop above only exits via an exception (cancellation, in practice) --
        # never a plain `return` -- so this runs exactly once, on shutdown. A waiter
        # that registered after the last snapshot (mid-pass, or during the
        # interval-wait sleep above) is not in `waiters` and was never notified by
        # the per-pass `finally`; without this, it stays parked in `select()`
        # forever whenever this loop does not run again. Re-snapshotting here picks
        # up exactly that gap. `close_waiter` on the CLI side unlinks a waiter's
        # FIFO once notified, so a waiter already notified by the loop above and
        # already closed is simply absent from this snapshot -- no double count.
        reconcile_wait.notify_waiters(reconcile_wait.snapshot_waiters(database_path), ok=False)


async def cleanup_all_containers(settings: Settings) -> None:
    """Stop and remove all of THIS instance's managed containers. Called on shutdown."""
    logger.info("Cleaning up all managed containers")
    instance_id = resolve_instance_id(settings)
    if instance_id is None:
        logger.error("Skipping shutdown cleanup: could not determine the instance id (%s)", instance_id_fault(settings))
        return
    try:
        client = _get_docker_client()
        try:
            managed = _list_managed_containers(client, instance_id)
            for name, container in managed.items():
                _remove_container(container)
        finally:
            client.close()
    except Exception:
        logger.exception("Failed to cleanup containers")
