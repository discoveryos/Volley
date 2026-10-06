#!/usr/bin/env sh
# install.sh - one-shot dependency check, build and install for Volley.
#
# Checks that the required packages are present, installs them when they are
# missing, then runs configure, make, optionally the test suite, and installs
# the binary, header and libraries. Works on Linux (apt/dnf/pacman/zypper/apk),
# macOS (Homebrew), Windows (MSYS2) and FreeBSD.
#
#   ./install.sh [options]
#
#   --prefix=DIR    install root (default /usr/local)
#   --jobs=N        parallel build jobs (default: all cores)
#   --deps-only     check/install dependencies and exit
#   --no-deps       never install packages, only report what is missing
#   -y, --yes       answer yes to package installs without prompting
#   --check         run "make check" before installing
#   --build-only    stop after building, do not install
#   --clean         "make clean" first
#   --uninstall     remove the installed files and exit
#   --help          this text
#
# All other arguments are passed through to ./configure.

set -eu

die() { printf '\ninstall.sh: %s\n' "$*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }
note() { printf '  %s\n' "$*"; }
usage() {
  cat <<'EOF'
volley install.sh - dependency check, build and install

usage: ./install.sh [options] [-- configure-args]

  --prefix=DIR    install root (default /usr/local)
  --jobs=N        parallel build jobs (default: all cores)
  -jN             same as --jobs=N
  --deps-only     check/install dependencies and exit
  --no-deps       never install packages, only report what is missing
  -y, --yes       do not prompt before installing packages
  --check         run "make check" before installing
  --build-only    stop after building, do not install
  --clean         "make clean" first
  --uninstall     remove the installed files and exit
  -h, --help      this text

any other argument is forwarded to ./configure, e.g.:
  ./install.sh --prefix=$HOME/.local -- --static-libs
EOF
}

# --- locate the source tree ----------------------------------------
SRC_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" 2>/dev/null && pwd -P) || SRC_DIR=.
cd "$SRC_DIR" || die "cannot enter source directory: $SRC_DIR"
[ -f configure ] && [ -f Makefile ] || \
  die "this does not look like a Volley source tree (missing configure/Makefile)"

# --- platform --------------------------------------------------------
UNAME=$(uname -s 2>/dev/null || echo unknown)
OS=unknown
case "$UNAME" in
  Linux)                  OS=linux ;;
  Darwin)                 OS=macos ;;
  MINGW*|MSYS*|CYGWIN*)   OS=windows ;;
  FreeBSD|OpenBSD|NetBSD) OS=bsd ;;
  *)                      OS=unknown ;;
esac
if [ "$OS" = linux ] && [ -r /proc/version ] && \
   grep -qi microsoft /proc/version 2>/dev/null; then
  OS=wsl
fi

# --- options ---------------------------------------------------------
PREFIX=/usr/local
JOBS=0
DO_CHECK=no
DO_INSTALL=yes
DO_CLEAN=no
UNINSTALL=no
DEPS_ONLY=no
DEPS_MODE=auto          # auto | never | only
ASSUME_YES=no
CONFIGURE_ARGS=

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix=*)   PREFIX=${1#--prefix=} ;;
    --jobs=*)     JOBS=${1#--jobs=} ;;
    -j*)          JOBS=${1#-j} ;;
    --check)      DO_CHECK=yes ;;
    --build-only) DO_INSTALL=no ;;
    --clean)      DO_CLEAN=yes ;;
    --uninstall)  UNINSTALL=yes ;;
    --deps-only)  DEPS_ONLY=yes; DEPS_MODE=only ;;
    --no-deps)    DEPS_MODE=never ;;
    -y|--yes)     ASSUME_YES=yes ;;
    --help|-h)    usage; exit 0 ;;
    --)           shift; while [ $# -gt 0 ]; do CONFIGURE_ARGS="$CONFIGURE_ARGS $1"; shift; done; break ;;
    --*)          printf 'install.sh: unknown option: %s (try --help)\n' "$1" >&2; exit 2 ;;
    *)            CONFIGURE_ARGS="$CONFIGURE_ARGS $1" ;;
  esac
  shift
done

# --- parallelism -----------------------------------------------------
if [ "$JOBS" -eq 0 ] 2>/dev/null; then
  JOBS=$(nproc 2>/dev/null || \
         getconf _NPROCESSORS_ONLN 2>/dev/null || \
         sysctl -n hw.ncpu 2>/dev/null || echo 1)
  case "$JOBS" in ''|*[!0-9]*) JOBS=1 ;; esac
fi

have() { command -v "$1" >/dev/null 2>&1; }

# --- privilege --------------------------------------------------------
run_privileged() {
  if [ "$(id -u 2>/dev/null || echo 1)" = 0 ]; then
    "$@"
  elif have sudo; then
    sudo "$@"
  elif [ "$OS" = windows ]; then
    # MSYS2/Git Bash: no sudo, the shell is already the user's privileges
    "$@"
  else
    return 1
  fi
}

pkg_root() {
  if [ "$(id -u 2>/dev/null || echo 1)" = 0 ]; then echo ""
  elif have sudo; then echo "sudo"
  else echo "__nopriv__"; fi
}

# --- package lists per package manager -------------------------------
# Each entry is "<package manager>|<packages>".
apt_pkgs()   { echo "build-essential pkg-config libssl-dev zlib1g-dev"; }
dnf_pkgs()   { echo "gcc make pkg-config openssl-devel zlib-devel"; }
yum_pkgs()   { echo "gcc make pkgconfig openssl-devel zlib-devel"; }
apk_pkgs()   { echo "build-base pkgconf openssl-dev zlib-dev"; }
pacman_pkgs(){ echo "base-devel pkgconf openssl zlib"; }
zypper_pkgs(){ echo "gcc make pkg-config libopenssl-devel zlib-devel"; }
xbps_pkgs()  { echo "base-devel pkg-config openssl-devel zlib-devel"; }
pkg_pkgs()   { echo "gmake pkgconf openssl"; }
brew_pkgs()  { echo "openssl@3 zlib pkg-config"; }
msys_pkgs()  { echo "base-devel mingw-w64-x86_64-toolchain mingw-w64-x86_64-openssl mingw-w64-x86_64-zlib mingw-w64-x86_64-pkgconf"; }

# what the current system actually needs, given its package manager
current_pkgmgr() {
  case "$OS" in
    windows) if have pacman; then echo msys2; else echo none; fi; return ;;
    macos)   if have brew; then echo brew; else echo none; fi; return ;;
  esac
  if have apt-get; then echo apt
  elif have dnf; then echo dnf
  elif have yum; then echo yum
  elif have pacman; then echo pacman
  elif have apk; then echo apk
  elif have zypper; then echo zypper
  elif have xbps-install; then echo xbps
  elif have pkg; then echo pkg
  else echo none
  fi
}

pkg_packages() {
  case "$1" in
    apt)    apt_pkgs ;;
    dnf)    dnf_pkgs ;;
    yum)    yum_pkgs ;;
    apk)    apk_pkgs ;;
    pacman) pacman_pkgs ;;
    zypper) zypper_pkgs ;;
    xbps)   xbps_pkgs ;;
    pkg)    pkg_pkgs ;;
    brew)   brew_pkgs ;;
    msys2)  msys_pkgs ;;
    *)      echo "" ;;
  esac
}

pkg_install_cmd() {
  # $1 = manager
  local pkgs
  pkgs=$(pkg_packages "$1")
  case "$1" in
    apt)    echo "apt-get update && apt-get install -y $pkgs" ;;
    dnf)    echo "dnf install -y $pkgs" ;;
    yum)    echo "yum install -y $pkgs" ;;
    apk)    echo "apk add $pkgs" ;;
    pacman) echo "pacman -Sy --needed --noconfirm $pkgs" ;;
    zypper) echo "zypper --non-interactive install $pkgs" ;;
    xbps)   echo "xbps-install -Sy $pkgs" ;;
    pkg)    echo "pkg install -y $pkgs" ;;
    brew)   echo "brew install $pkgs" ;;
    msys2)  echo "pacman -Sy --needed --noconfirm $pkgs" ;;
    *)      echo "" ;;
  esac
}

# --- capability probes ------------------------------------------------
MISSING_TOOLS=
MISSING_LIBS=

probe_tools() {
  MISSING_TOOLS=
  if [ -n "${CC:-}" ]; then
    have "$CC" || MISSING_TOOLS="$MISSING_TOOLS $CC"
  else
    local found=no c
    for c in cc clang gcc tcc; do
      if have "$c"; then found=yes; break; fi
    done
    [ "$found" = yes ] || MISSING_TOOLS="$MISSING_TOOLS cc"
  fi
  have make || MISSING_TOOLS="$MISSING_TOOLS make"
  have install || MISSING_TOOLS="$MISSING_TOOLS install"
}

probe_libs() {
  MISSING_LIBS=
  local cc="${CC:-}"
  if [ -z "$cc" ]; then
    for c in cc clang gcc tcc; do
      if have "$c"; then cc=$c; break; fi
    done
  fi
  [ -n "$cc" ] || { MISSING_LIBS="openssl zlib"; return 0; }

  local libs="-lssl -lcrypto -lz" cflags=
  if have pkg-config && pkg-config --exists openssl zlib 2>/dev/null; then
    libs=$(pkg-config --libs openssl zlib 2>/dev/null || echo "$libs")
    cflags=$(pkg-config --cflags openssl zlib 2>/dev/null || echo "")
  fi

  # compile + link: catches missing headers and missing libraries separately
  printf '#include <openssl/ssl.h>\n#include <zlib.h>\nint main(void){return 0;}\n' \
    | "$cc" -x c - -o /dev/null $cflags $libs >/dev/null 2>&1 \
    || MISSING_LIBS="openssl zlib"
}

deps_missing() {
  probe_tools
  probe_libs
  [ -z "$MISSING_TOOLS$MISSING_LIBS" ]
}

print_missing() {
  say ""
  if [ -n "$MISSING_TOOLS$MISSING_LIBS" ]; then
    say "missing packages:"
    [ -n "$MISSING_TOOLS" ] && note "tools:$MISSING_TOOLS"
    [ -n "$MISSING_LIBS" ] && note "libraries:$MISSING_LIBS"
  else
    say "all dependencies are present"
  fi
  local mgr pkgs
  mgr=$(current_pkgmgr)
  pkgs=$(pkg_packages "$mgr")
  say ""
  if [ "$mgr" = none ] || [ -z "$pkgs" ]; then
    say "no supported package manager detected; install manually:"
    case "$OS" in
      macos)  say "  xcode-select --install; brew install openssl@3 zlib pkg-config" ;;
      windows) say "  use an MSYS2 shell: pacman -S base-devel mingw-w64-x86_64-toolchain \\"
              say "            mingw-w64-x86_64-openssl mingw-w64-x86_64-zlib mingw-w64-x86_64-pkgconf" ;;
      *)      say "  a C compiler, make, OpenSSL headers/libs and zlib headers/libs" ;;
    esac
    return
  fi
  say "install them with:"
  local root; root=$(pkg_root)
  case "$root" in
    "")         say "  $(pkg_install_cmd "$mgr")" ;;
    __nopriv__) say "  $(pkg_install_cmd "$mgr")   # run as root / with sudo" ;;
    *)          say "  $(pkg_root) $(pkg_install_cmd "$mgr")" ;;
  esac
}

install_deps() {
  local mgr pkgs root
  mgr=$(current_pkgmgr)
  pkgs=$(pkg_packages "$mgr")
  [ "$mgr" != none ] && [ -n "$pkgs" ] || return 1

  say ""
  say "== dependencies =="
  note "package manager $mgr"
  note "packages       $pkgs"

  if [ "$ASSUME_YES" != yes ]; then
    if [ -t 0 ]; then
      printf 'install these packages now? [y/N] '
      read -r reply || reply=n
      case "$reply" in
        y|Y|yes|YES) ;;
        *) say "skipping package installation"; return 1 ;;
      esac
    else
      say "non-interactive shell: re-run with -y to install packages"
      return 1
    fi
  fi

  root=$(pkg_root)
  case "$root" in
    __nopriv__) die "no root/sudo available to install packages ($pkgs)" ;;
    "")         sh -c "$(pkg_install_cmd "$mgr")" ;;
    *)          sh -c "$(pkg_root) $(pkg_install_cmd "$mgr")" ;;
  esac

  # re-probe after installing
  probe_tools
  probe_libs
  if [ -n "$MISSING_TOOLS$MISSING_LIBS" ]; then
    say "still missing after install: $MISSING_TOOLS $MISSING_LIBS"
    return 1
  fi
  note "dependencies satisfied"
  return 0
}

# --- uninstall -------------------------------------------------------
if [ "$UNINSTALL" = yes ]; then
  say "uninstalling Volley from $PREFIX"
  for d in "$PREFIX/lib" "$PREFIX/lib64"; do
    rm -f "$d/libvolley.a" "$d/libvolley.so" "$d/libvolley.so.1" \
          "$d/libvolley.so.1.0.0" 2>/dev/null || true
  done
  rm -f "$PREFIX/include/libvolley.h" 2>/dev/null || \
    run_privileged rm -f "$PREFIX/include/libvolley.h" || true
  if [ -f "$PREFIX/bin/volley" ]; then
    rm -f "$PREFIX/bin/volley" 2>/dev/null || \
      run_privileged rm -f "$PREFIX/bin/volley" || true
  fi
  say "done"
  exit 0
fi

# --- banner ----------------------------------------------------------
say "_   _       _ _"
say "| | | |     | | |"
say "| | | | ___ | | | ___ _   _"
say "| | | |/ _ \\| | |/ _ \\ | | |"
say "\\ \\_/ / (_) | | |  __/ |_| |"
say " \\___/ \\___/|_|_|\\___|\\__, |"
say "                       __/ |"
say "                      |___/"
say ""
say "volley installer"
note "platform     $OS ($UNAME)"
note "source       $SRC_DIR"
note "prefix       $PREFIX"
note "jobs         $JOBS"

# --- dependency stage -------------------------------------------------
probe_tools
probe_libs

if [ -n "$MISSING_TOOLS$MISSING_LIBS" ]; then
  print_missing
  if [ "$DEPS_MODE" = never ]; then
    die "dependencies are missing (--no-deps given)"
  fi
  install_deps || print_missing
fi

probe_tools
probe_libs
if [ -n "$MISSING_TOOLS$MISSING_LIBS" ]; then
  print_missing
  die "dependencies not satisfied; install the packages above and re-run"
fi

if [ "$DEPS_ONLY" = yes ]; then
  say ""
  say "all dependencies present"
  exit 0
fi

CC_CMD=${CC:-}
if [ -z "$CC_CMD" ]; then
  for c in cc clang gcc tcc; do
    if have "$c"; then CC_CMD=$c; break; fi
  done
fi
LDLIBS_PROBE=$( (have pkg-config && pkg-config --exists openssl zlib) \
                && pkg-config --libs openssl zlib || echo "-lssl -lcrypto -lz" )
note "compiler     $CC_CMD"
note "deps         $LDLIBS_PROBE"

# --- build -----------------------------------------------------------
say ""
say "== configure =="
[ "$DO_CLEAN" = yes ] && { say "== make clean =="; make clean >/dev/null 2>&1 || true; }

# shellcheck disable=SC2086
./configure --prefix="$PREFIX" $CONFIGURE_ARGS

say ""
say "== make -j$JOBS =="
make -j"$JOBS"

if [ "$DO_CHECK" = yes ]; then
  say ""
  say "== make check =="
  make check
fi

# --- install ---------------------------------------------------------
if [ "$DO_INSTALL" != yes ]; then
  say ""
  say "build complete (no install): $PWD/volley"
  "$PWD/volley" --version
  exit 0
fi

say ""
say "== install =="

if [ -d "$PREFIX" ] && [ -w "$PREFIX" ]; then
  make install
else
  parent=$(dirname "$PREFIX")
  if [ -d "$parent" ] && [ -w "$parent" ]; then
    make install
  else
    run_privileged make install || \
      die "cannot write to $PREFIX (re-run as root, or pass --prefix=\$HOME/.local)"
  fi
fi

# --- post-install ----------------------------------------------------
say ""
say "== installed =="
installed_ok=yes
for f in "$PREFIX/bin/volley" "$PREFIX/include/libvolley.h" "$PREFIX/lib/libvolley.a"; do
  if [ -e "$f" ]; then note "ok   $f"; else note "MISS $f"; installed_ok=no; fi
done

"$PREFIX/bin/volley" --version 2>/dev/null || installed_ok=no

case ":$PATH:" in
  *":$PREFIX/bin:"*) ;;
  *) say ""
     say "note: $PREFIX/bin is not on your PATH; add it with:"
     say "  export PATH=\"$PREFIX/bin:\$PATH\"" ;;
esac

case "$OS" in
  windows) say ""
           say "note: Windows builds are MSYS2/MinGW executables; run them from an"
           say "      MSYS2 or Windows shell, not from cmd.exe." ;;
esac

[ "$installed_ok" = yes ] || die "installation did not complete cleanly"

say ""
say "volley installed successfully"
