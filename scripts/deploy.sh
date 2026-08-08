#!/usr/bin/env bash
# One-command deploy for a Postern host: preconditions -> build -> up -> reconcile -> verify.
#
# Why this exists (issue #196): `local/shadowsocks-server` is built OUTSIDE compose
# while every other image is built by it, so a deploy is two commands that look
# independent. Running only one leaves a half-new, healthy, WRONG stack. Issue #195's
# scripts/verify-deploy.py is the gate that catches it; this script is what runs it
# at the right time, after a guaranteed-complete reconcile pass.
#
# The script never passes -f or --profile to `docker compose`: compose reads
# COMPOSE_FILE / COMPOSE_PROFILES from the repo-root .env, so every documented
# overlay combination (cert / gateway / edge) works unchanged.
#
# Tested by portal/tests/test_deploy_script.py, which puts fake `git`, `docker`, and
# `python3` executables on PATH and asserts on the exact commands issued and their
# order.

set -Eeuo pipefail
# inherit_errexit is load-bearing, not decoration: without it `set -e` does NOT apply
# inside $( ), so a failing command in a command substitution is silently swallowed
# and only the assignment's own status is checked. `resolve_shadowsocks_image` and
# `resolve_git_revision` both run commands inside a substitution; without this line a
# failed portal build or a failed revision lookup lets the deploy continue with STALE
# or empty data -- precisely the half-new-and-wrong stack this script exists to
# prevent. Requires bash >= 4.4, and shellcheck will not flag the omission
# (SC2310/SC2311 are optional checks, off by default).
shopt -s inherit_errexit
trap 'echo "deploy.sh: aborted at line ${LINENO} (exit $?)" >&2' ERR

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"

allow_dirty=0
allow_behind=0
allow_branch=0
do_fetch=1
# Bounded, not unbounded: reconcile_and_wait blocks on the reconciler's single,
# unsupervised background task (reconciler.reconciliation_loop). If that task ever
# dies for a reason unrelated to a slow pass, an unbounded wait here would hang this
# script -- and every future deploy after it -- forever with no diagnostic. 30
# minutes is generous for "recreating many tunnel containers sequentially" while
# still being a real bound; --wait-timeout overrides it explicitly.
readonly DEFAULT_WAIT_TIMEOUT="1800"
wait_timeout="$DEFAULT_WAIT_TIMEOUT"
dirty_marker=""
GIT_REVISION=""
expected_tunnels=""

# Output helpers =======================================================================================================
log() {
    printf '==> %s\n' "$*"
}

warn() {
    printf 'deploy.sh: warning: %s\n' "$*" >&2
}

die() {
    printf 'deploy.sh: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Usage: scripts/deploy.sh [options]

Deploys this checkout: builds the shadowsocks image, rebuilds and restarts the
compose stack, reconciles the tunnel containers, and verifies (scripts/verify-
deploy.py --tunnels) that everything running is on the images just built.

Options:
  --allow-dirty    Deploy with uncommitted changes in the worktree.
  --allow-behind   Deploy even though origin/main has commits this checkout lacks.
  --allow-branch   Deploy a revision that is not exactly origin/main.
  --no-fetch       Do not contact the remote; compare against the last known origin/main.
  --wait-timeout N Fail if the reconcile pass has not finished within N seconds
                   (positive number; 0 is not a bound and is rejected). Defaults to
                   1800 (30 minutes) -- generous for recreating many tunnels
                   sequentially, but still a real bound: without one, a dead
                   reconciler background task would hang this script forever.
  -h, --help       Show this help and exit.
EOF
}

# Argument parsing =====================================================================================================
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
        --allow-dirty) allow_dirty=1 ;;
        --allow-behind) allow_behind=1 ;;
        --allow-branch) allow_branch=1 ;;
        --no-fetch) do_fetch=0 ;;
        --wait-timeout)
            shift
            wait_timeout="${1:-}"
            # Validated here, not by the CLI at the end of the deploy: `--wait-timeout
            # abc` or a swallowed following flag (`--wait-timeout --no-fetch`) must not
            # cost two image builds and a stack restart before failing. `0` is rejected
            # because `postern reconcile --wait` reads it as "wait forever", the
            # opposite of a bound -- and unbounded is already the default.
            if ! [[ "$wait_timeout" =~ ^[0-9]+(\.[0-9]+)?$ ]] || [[ "$wait_timeout" =~ ^0+(\.0+)?$ ]]; then
                die "--wait-timeout needs a positive number of seconds (got: '${wait_timeout}')"
            fi
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            die "unknown option: $1"
            ;;
        esac
        shift
    done
}

# Preconditions ========================================================================================================
check_worktree_clean() {
    local dirty
    dirty="$(git status --porcelain)"

    if [[ -z "$dirty" ]]; then
        return 0
    fi
    if [[ "$allow_dirty" == 1 ]]; then
        dirty_marker=" (dirty worktree)"
        warn "worktree is dirty; deploying it anyway (--allow-dirty)"
        return 0
    fi

    printf '%s\n' "$dirty" >&2
    die "worktree is dirty -- commit, stash, or pass --allow-dirty"
}

check_revision() {
    if [[ "$do_fetch" == 1 ]]; then
        if ! git fetch --quiet origin main; then
            die "git fetch origin main failed -- pass --no-fetch to deploy without contacting the remote"
        fi
    else
        warn "--no-fetch: comparing against the last known origin/main, which may be stale"
    fi

    local head upstream ancestor_rc
    head="$(git rev-parse HEAD)"
    if ! upstream="$(git rev-parse origin/main 2>/dev/null)"; then
        die "no origin/main ref in this checkout -- run 'git fetch origin main' first"
    fi

    ancestor_rc=0
    git merge-base --is-ancestor origin/main HEAD || ancestor_rc=$?
    if [[ "$ancestor_rc" -gt 1 ]]; then
        die "git merge-base failed (exit ${ancestor_rc}) -- cannot establish what this checkout contains"
    fi
    if [[ "$ancestor_rc" == 1 ]]; then
        if [[ "$allow_behind" != 1 ]]; then
            die "HEAD (${head:0:7}) is missing commits that are on origin/main (${upstream:0:7}) -- git pull, or pass --allow-behind"
        fi
        warn "deploying a revision that is missing commits from origin/main (--allow-behind)"
    fi

    if [[ "$head" != "$upstream" ]]; then
        if [[ "$allow_branch" != 1 ]]; then
            die "HEAD (${head:0:7}) is not origin/main (${upstream:0:7}) -- deploying a branch build must be explicit; pass --allow-branch"
        fi
        warn "deploying ${head:0:7}, which is not origin/main (--allow-branch)"
    fi
}

# Refuse early on a broken compose setup (a missing .env is a hard failure for the
# portal's `env_file:`). Without this the operator finds out at `compose up`, minutes
# later, after two image builds -- which contradicts the whole "refuse before you
# touch anything" premise of the precondition gate.
check_compose_config() {
    if ! docker compose config -q; then
        die "docker compose config failed -- fix .env / COMPOSE_FILE before deploying"
    fi
}

print_preflight() {
    cat <<'EOF'
==> This deploy restarts the portal. On shutdown the portal removes EVERY ss-*
    tunnel container and the reconciler recreates them seconds later, so every
    user's tunnel drops briefly. Path tokens are unchanged; client configs stay valid.
EOF

    # `config --services` resolves COMPOSE_FILE + COMPOSE_PROFILES exactly as the
    # real `up` will, so this note appears if and only if the provisioner is in play.
    # Captured into a variable rather than piped into grep: under `set -o pipefail`,
    # `docker … | grep -q` can fail the pipeline on SIGPIPE once grep exits early,
    # which would silently drop the notice.
    #
    # No `|| true` here: `check_compose_config` has already parsed the same files a
    # moment ago, so a failure at this point is a real one and `set -e` should stop
    # the deploy rather than quietly skipping the notice.
    local services
    services="$(docker compose config --services)"
    if [[ $'\n'"${services}"$'\n' == *$'\n'provisioner$'\n'* ]]; then
        cat <<'EOF'
==> The provisioner is active. Under compose.cert.yaml, nginx and mta wait on its
    healthcheck: a provisioner that cannot reach its DNS provider (or whose token
    lacks Zone Settings:Edit) blocks startup instead of degrading, and the
    `compose up` below will sit there rather than fail fast.
EOF
    fi
}

# Build provenance =====================================================================================================
# Same oracle scripts/verify-deploy.py uses for its own --expected-revision default,
# invoked the same way its own docs prescribe: `--print-revision` recomputes from git
# (appending -dirty for an unclean tree) rather than trusting anything already in the
# shell's environment.
resolve_git_revision() {
    log "Resolving the git revision to stamp into image labels"
    GIT_REVISION="$(python3 scripts/verify-deploy.py --print-revision)"
    export GIT_REVISION
}

# Tunnel image =========================================================================================================
# The tag to build is whatever the portal's Settings will resolve at runtime
# (SHADOWSOCKS_IMAGE, default local/shadowsocks-server). compose hands the portal that
# variable through `env_file: .env` only -- never through the deploying shell -- so the
# only way to be sure we build the tag the reconciler will look up is to ask the portal
# image itself. `compose run` applies the identical env_file. Re-implementing compose's
# dotenv parser here would be a second source of truth, and any disagreement between
# the two is a silent wrong-image deploy.
resolve_shadowsocks_image() {
    local image
    log "Resolving the tunnel image tag from the portal's own settings" >&2
    docker compose build portal >&2
    image="$(docker compose run --rm --no-deps -T portal \
        python -c 'from postern.settings import Settings; print(Settings().shadowsocks_image)')"
    image="${image%$'\r'}"

    if [[ -z "$image" ]]; then
        die "the portal resolved an empty SHADOWSOCKS_IMAGE -- fix or remove that line in .env"
    fi
    printf '%s\n' "$image"
}

build_shadowsocks_image() {
    local image
    image="$(resolve_shadowsocks_image)"
    log "Building ${image} (compose does not build this one; context is the repo root)"
    docker build -f shadowsocks/Dockerfile --build-arg GIT_REVISION="$GIT_REVISION" -t "$image" .
}

# Deploy steps =========================================================================================================
compose_up() {
    # No -f / --profile: compose reads COMPOSE_FILE and COMPOSE_PROFILES from the
    # repo-root .env, so every documented overlay combination works unchanged.
    # GIT_REVISION is already exported (resolve_git_revision), so compose.yaml's
    # `build.args: GIT_REVISION: ${GIT_REVISION:-}` forwards it to every first-party
    # image it builds.
    log "Rebuilding and restarting the compose stack"
    docker compose up -d --build
}

reconcile_and_wait() {
    # wait_timeout always has a value: DEFAULT_WAIT_TIMEOUT unless --wait-timeout
    # overrode it. See the top-of-file comment on DEFAULT_WAIT_TIMEOUT for why this
    # script never asks for an unbounded wait.
    log "Reconciling tunnel containers (blocks until the pass finishes, up to ${wait_timeout}s)"
    docker compose exec -T portal postern reconcile --wait --wait-timeout "$wait_timeout"
}

# Expected tunnel set ==================================================================================================
# Read AFTER the wait and as late as possible -- which narrows, but cannot close,
# the expected-set/container-set race documented in docs/operations/index.md.
#
# No timeout wrapper, unlike reconcile_and_wait's --wait-timeout: that one bounds a
# wait on the reconciler's single unsupervised background task, which can die
# independently. This is an ordinary short-lived command in a container that
# answered one a moment ago, and it hangs exactly as far as any other
# `docker compose exec` in this script does.

# Prints the ss-* container names this deployment should have, one per line. Returns
# 1 without printing if the portal's answer is not a clean name list -- callers
# decide whether that is fatal. `postern connection tunnels` exits non-zero when the
# portal cannot resolve its own instance id, because the reconciler then creates
# nothing and the list would be a lie. stdout only: warnings go to stderr.
read_expected_tunnels() {
    local out line
    out="$(docker compose exec -T portal postern connection tunnels)" || return 1
    out="${out//$'\r'/}"
    while IFS= read -r line; do
        if [[ -z "$line" ]]; then
            continue
        fi
        # An `[[ ... ]] && continue` one-liner would be a live grenade under
        # `set -e`: the list's status is the test's, so a non-empty line would
        # return 1 and kill the script.
        [[ "$line" =~ ^ss-[^[:space:]]+$ ]] || return 1
    done <<<"$out"
    printf '%s\n' "$out"
}

resolve_expected_tunnels() {
    local names
    log "Asking the portal which tunnels this deployment should have" >&2
    # shellcheck disable=SC2310  # read_expected_tunnels already `return 1`s explicitly
    # after every command that can fail (see its own body) -- it never relies on `set
    # -e` to stop it, so disabling errexit for the call is a no-op here, not a hole.
    if ! names="$(read_expected_tunnels)"; then
        # Never fall back to a setless verification: that would turn a broken
        # portal into a silently WEAKER gate, which is the failure this whole step
        # exists to remove.
        die "the portal did not report a usable tunnel list"
    fi
    printf '%s\n' "$names"
}

# Verification (issue #195) =============================================================================================
# scripts/verify-deploy.py is the gate: everything above can succeed while the stack
# still runs last month's images. `--tunnels` is safe here specifically because
# reconcile_and_wait already blocked on a completed pass -- without that guarantee
# `--tunnels` would race the reconciler's asynchronous post-restart recreation.
#
# Exit codes are three-valued and the distinction is real: 1 means the deployment is
# stale, 2 means the gate itself could not run (bad environment, not a verdict). Both
# abort this script, but the message told to the operator must not conflate them.
#
# `--expected-tunnels-from` is what makes "zero tunnel containers" a verdict rather
# than a SKIP. Sound here for the same reason `--tunnels` is -- reconcile_and_wait
# already blocked on a completed pass.
run_verification() {
    local -a extra=()
    if [[ "$allow_dirty" == 1 ]]; then
        # The build carries no committed revision either way; tell the gate what the
        # operator already acknowledged instead of letting its own dirty-checkout
        # check fail a deploy that was allowed on purpose.
        extra+=(--allow-dirty)
    fi

    log "Verifying the deploy actually took (scripts/verify-deploy.py --tunnels)"
    local rc=0
    python3 scripts/verify-deploy.py --tunnels --expected-tunnels-from - "${extra[@]}" \
        <<<"$expected_tunnels" || rc=$?
    if [[ "$rc" == 0 ]]; then
        return 0
    fi
    if [[ "$rc" != 1 ]]; then
        # Exit 2: the gate aborted before producing any tunnel row, so a "the set
        # changed" note would blame a row that does not exist -- and would spend
        # another Docker round-trip on a stack that may be exactly what is broken.
        die "deploy verification could not run (exit ${rc}) -- see the message above; this is not a verdict on the deploy"
    fi

    # Only on a real verdict, so the happy path pays nothing. The expected set and
    # the container listing were taken at different moments; a set that has since
    # moved means a connection was added or disabled mid-verification, which
    # produces exactly the tunnel rows the gate just printed. This does not clear
    # the failure -- other rows may be real -- it stops the operator from hunting
    # the reconciler. The re-read's STATUS is what decides whether it is usable --
    # not whether it printed anything. A successful empty re-read (every connection
    # was disabled or deleted mid-verification) is the case that most needs the
    # note, since every surviving container then shows up as surplus.
    local reread="" reread_ok=1
    # shellcheck disable=SC2310  # see resolve_expected_tunnels' identical comment
    reread="$(read_expected_tunnels)" || reread_ok=0
    if [[ "$reread_ok" == 1 && "$reread" != "$expected_tunnels" ]]; then
        warn "the set of enabled connections changed during verification. If the failure above is a tunnel row, that change is the cause, not the reconciler: re-run scripts/deploy.sh, or scripts/verify-deploy.py --tunnels --expected-tunnels-from - with a fresh \`postern connection tunnels\`"
    fi
    die "deploy verification failed -- the running stack is not provably on the images just built (see the checks above)"
}

# Main =================================================================================================================
main() {
    cd "$repo_root"
    parse_args "$@"
    check_worktree_clean
    check_revision
    check_compose_config
    print_preflight
    resolve_git_revision
    build_shadowsocks_image
    compose_up
    reconcile_and_wait
    expected_tunnels="$(resolve_expected_tunnels)"
    run_verification
    log "Deploy complete: $(git rev-parse --short HEAD)${dirty_marker}"
}

main "$@"
