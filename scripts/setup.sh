#!/usr/bin/env bash
# Builds, tests and installs patty, then lets the installed binary read other
# processes. Asks for the sudo password once, right at the start.
set -euo pipefail

usage() {
    cat <<'EOF'
usage: scripts/setup.sh [--prefix DIR] [--no-setcap] [--mcp] [--jobs N]

  --prefix DIR   install location (default ~/.local)
  --no-setcap    skip the capability step, no sudo at all
  --mcp          also set up the optional MCP server (Python venv in mcp/.venv)
  --jobs N       parallel build jobs (default 4)

Steps: configure, build, test, install, then sudo setcap cap_sys_ptrace=ep
on the installed binary and build/patty. With --mcp, the venv comes first.
EOF
}

prefix="$HOME/.local"
want_setcap=1
want_mcp=0
jobs=4
while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix)     prefix="${2:?--prefix needs a directory}"; shift 2 ;;
        --no-setcap)  want_setcap=0; shift ;;
        --mcp)        want_mcp=1; shift ;;
        --jobs)       jobs="${2:?--jobs needs a number}"; shift 2 ;;
        -h|--help)    usage; exit 0 ;;
        *)            usage >&2; exit 2 ;;
    esac
done

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build="$repo/build"
prefix="$(mkdir -p "$prefix" && cd "$prefix" && pwd)"

bold=$'\033[1m' dim=$'\033[2m' reset=$'\033[0m'
[[ -t 1 ]] || bold='' dim='' reset=''
step() { printf '\n%s==> %s%s\n' "$bold" "$*" "$reset"; }
die()  { printf 'setup: %s\n' "$*" >&2; exit 1; }

# Low priority so the machine stays usable while compiling.
quiet() {
    if command -v ionice >/dev/null; then nice -n 19 ionice -c3 "$@"; else nice -n 19 "$@"; fi
}

# --- preflight -----------------------------------------------------------

for tool in cmake ninja; do
    command -v "$tool" >/dev/null || die "$tool is missing"
done
if (( want_mcp )); then
    command -v python3 >/dev/null || die "python3 is missing (needed for --mcp)"
fi
command -v c++ >/dev/null || command -v g++ >/dev/null || command -v clang++ >/dev/null \
    || die "no C++ compiler (c++, g++ or clang++)"

setcap_bin="" getcap_bin="" sudo=""
if (( want_setcap )); then
    [[ "$(uname -s)" == Linux ]] || die "the capability step is Linux only, use --no-setcap"
    setcap_bin="$(command -v setcap || echo /usr/sbin/setcap)"
    getcap_bin="$(command -v getcap || echo /usr/sbin/getcap)"
    [[ -x "$setcap_bin" && -x "$getcap_bin" ]] || die "setcap/getcap not found (libcap), or use --no-setcap"
    if (( EUID != 0 )); then
        command -v sudo >/dev/null || die "sudo is missing, or use --no-setcap"
        sudo="sudo"
    fi
fi

printf '%spatty setup%s\n' "$bold" "$reset"
printf '  build    %s\n' "$build"
printf '  install  %s\n' "$prefix"
if (( want_setcap )); then
    printf '  access   cap_sys_ptrace on %s/bin/patty and build/patty\n' "$prefix"
    if [[ -n "$sudo" ]]; then
        printf '\n%ssudo asks for your password now, once. Nothing later prompts.%s\n' "$dim" "$reset"
        sudo -v
        # Keep the sudo timestamp fresh while building; stops when the script ends.
        ( while kill -0 $$ 2>/dev/null; do sudo -n -v 2>/dev/null || exit; sleep 50; done ) &
        keepalive=$!
        trap 'kill "$keepalive" 2>/dev/null || true' EXIT
    fi
fi

# --- MCP server (optional) -----------------------------------------------

if (( want_mcp )); then
    step "MCP server venv"
    venv="$repo/mcp/.venv"
    if [[ ! -x "$venv/bin/python" ]]; then
        python3 -m venv "$venv"
    fi
    if ! "$venv/bin/python" -c 'import fastmcp' 2>/dev/null; then
        "$venv/bin/pip" install --quiet --disable-pip-version-check fastmcp
    fi
    echo "fastmcp $("$venv/bin/python" -c 'import fastmcp; print(fastmcp.__version__)')"
fi

# --- build, test, install ------------------------------------------------

step "Configure"
quiet cmake -S "$repo" -B "$build" -G Ninja -DCMAKE_BUILD_TYPE=Release >/dev/null

step "Build"
quiet cmake --build "$build" -j "$jobs"

step "Test"
quiet ctest --test-dir "$build" --output-on-failure | tail -n 3

step "Install"
cmake --install "$build" --prefix "$prefix" >/dev/null
echo "$prefix/bin/patty"

# --- capability ----------------------------------------------------------

if (( want_setcap )); then
    step "Allow reading other processes"
    # patty only calls process_vm_readv, but the kernel checks ptrace
    # permission for it. 700 keeps other users on this machine from using the
    # binary to read memory they could not read themselves.
    for bin in "$prefix/bin/patty" "$build/patty"; do
        chmod 700 "$bin"
        $sudo "$setcap_bin" cap_sys_ptrace=ep "$bin"
        "$getcap_bin" "$bin" | grep -q cap_sys_ptrace \
            || die "setcap did not stick on $bin (filesystem without xattr support?)"
        echo "$("$getcap_bin" "$bin")"
    done
fi

# --- summary -------------------------------------------------------------

step "Done"
echo "patty $("$prefix/bin/patty" --version)"
case ":$PATH:" in
    *":$prefix/bin:"*) ;;
    *) printf '%s/bin is not on your PATH yet:  export PATH="%s/bin:$PATH"\n' "$prefix" "$prefix" ;;
esac
if (( want_mcp )); then
    echo "MCP server ready, see mcp/README.md for the client config."
fi
cat <<EOF

  patty                         interactive shell
  patty list --name <process>   regions of a running process
  find_package(patty)           in CMake, with CMAKE_PREFIX_PATH=$prefix

EOF
if (( want_setcap )); then
    echo "Rebuilding drops the capability. Run this script again afterwards."
fi
