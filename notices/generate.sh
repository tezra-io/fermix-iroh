#!/usr/bin/env bash
# Writes THIRD-PARTY-NOTICES.txt: fermix-iroh's own licence, then the notices
# of everything the four release targets compile in. CI and the release run it
# and refuse a committed copy that differs.
#
# It needs the toolchain and the cargo-about that ci.yml pins, since another
# version of either renders another file:
#   rustup toolchain install <RUST_TOOLCHAIN> --profile minimal
#   cargo install --locked --features cli cargo-about@<CARGO_ABOUT_VERSION>
# It reads crate sources through cargo and fetches from GitHub the LICENSE-MIT
# that some crates leave out of their package (notices/about.toml).
set -euo pipefail

cd "$(dirname "$0")/.."

pin() { sed -n "s/^  $1: \"\(.*\)\"\$/\1/p" .github/workflows/ci.yml; }
toolchain="$(pin RUST_TOOLCHAIN)"
about_version="$(pin CARGO_ABOUT_VERSION)"
if [ -z "$toolchain" ] || [ -z "$about_version" ]; then
  echo "error: RUST_TOOLCHAIN or CARGO_ABOUT_VERSION missing from ci.yml's env" >&2
  exit 1
fi

# The Linux binaries link what Rust ships in self-contained/ for its
# *-linux-musl targets, not the system's libraries (musl-gcc only compiles
# ring's and blake3's C): musl's libc and crt objects, built from the musl that
# src/ci/docker/scripts/musl.sh in rust-lang/rust names, and LLVM's libunwind
# and compiler-rt crtbegin/crtend, built from the LLVM rustc reports. The
# aarch64 binary also links compiler-rt's outline atomics, which the standard
# library builds into compiler_builtins.
case "$toolchain" in
  1.97.1) musl=1.2.5 llvm=22.1.6 ;;
  *)
    echo "error: which musl and LLVM does Rust $toolchain bundle? Vendor musl's" >&2
    echo "COPYRIGHT as notices/musl-<version>-COPYRIGHT and the LICENSE.TXT of LLVM's" >&2
    echo "libunwind and compiler-rt as notices/llvm-<version>-<component>-LICENSE.TXT," >&2
    echo "and map the toolchain to them here." >&2
    exit 1
    ;;
esac
found="$(rustc "+$toolchain" -vV | sed -n 's/^LLVM version: //p')"
if [ "$found" != "$llvm" ]; then
  echo "error: Rust $toolchain reports LLVM ${found:-none}, not $llvm" >&2
  exit 1
fi

# The crates allowed on a licence's standard text, whose copyright line is a
# placeholder: their packages ship no licence file, and upstream has none with
# a copyright line to clarify from, so the template names each one's authors
# and repository instead. A crate that loses its licence file lands on a
# standard text without a word from cargo-about, so the script refuses any
# crate there that is not listed here, and any listed one that no longer is.
standard_text_crates=(
  block2
  dispatch2
  enum-assoc
  objc2
  objc2-core-foundation
  objc2-encode
  objc2-security
  objc2-system-configuration
)

found="$(cargo-about --version 2>/dev/null)" || found="no cargo-about"
if [ "$found" != "cargo-about $about_version" ]; then
  echo "error: found $found; install cargo-about $about_version:" >&2
  echo "  cargo install --locked --features cli cargo-about@$about_version" >&2
  exit 1
fi

std_notice="$(rustc "+$toolchain" --print sysroot)/share/doc/rust/COPYRIGHT-library.html"
graph="$(mktemp)"
crates="$(mktemp)"
log="$(mktemp)"
out="$(mktemp)"
trap 'rm -f "$graph" "$crates" "$log" "$out"' EXIT

# cargo-about only warns when a clarification no longer matches its checksum,
# and then guesses from the files instead. A warning is an error here.
about() {
  local status=0
  cargo "+$toolchain" about generate --locked --fail -c notices/about.toml "$@" \
    2>"$log" || status=$?
  cat "$log" >&2
  if [ "$status" -ne 0 ] || grep -q 'WARN\|ERROR' "$log"; then
    echo "error: cargo-about failed or warned; THIRD-PARTY-NOTICES.txt is unchanged" >&2
    exit 1
  fi
}

# Compares the crates on a standard text with standard_text_crates.
standard_text() {
  python3 -I - "$graph" "${standard_text_crates[@]}" <<'EOF'
import json, sys

graph = json.load(open(sys.argv[1], encoding="utf-8"))
listed = set(sys.argv[2:])
found = {
    used["crate"]["name"]
    for licence in graph["licenses"]
    if licence["source_path"] is None
    for used in licence["used_by"]
}
for name in sorted(found - listed):
    print(f"error: {name} has no licence text of its own; clarify it in notices/about.toml", file=sys.stderr)
for name in sorted(listed - found):
    print(f"error: {name} has its own licence text now; drop it from standard_text_crates", file=sys.stderr)
if found != listed:
    print("error: THIRD-PARTY-NOTICES.txt is unchanged", file=sys.stderr)
    sys.exit(1)
EOF
}

about --format json -o "$graph"
standard_text
about -o "$crates" notices/about.hbs

# The standard library's notice is the toolchain's own HTML page; this renders
# it as text, its licence texts verbatim.
std_text() {
  python3 -I - "$std_notice" <<'EOF'
import html, re, sys

page = open(sys.argv[1], encoding="utf-8").read()
body = page[page.index("<body>") + len("<body>"):page.index("</body>")]
blocks = []
for i, part in enumerate(re.split(r"<pre>(.*?)</pre>", body, flags=re.S)):
    if i % 2:
        blocks.append(html.unescape(part).lstrip("\n").rstrip())
        continue
    part = re.sub(r"\s+", " ", part)
    part = re.sub(r"</?(?:h[1-3]|p|ul|li|div|details|summary|br)\b[^>]*>", "\n", part)
    lines = html.unescape(re.sub(r"<[^>]+>", "", part)).split("\n")
    blocks.extend(line.strip() for line in lines if line.strip())
print("\n\n".join(blocks))
EOF
}

# cargo-about's part, with Cargo.lock's checksum in place of each mark the
# template leaves as LOCK_SHA256(<name> <version>), and each
# SOURCE_PATH(<path>) without this machine's cargo home: cargo-about gives a
# packaged file's absolute path, which becomes <name>-<version>/<file> as in
# the registry, and a clarified file's path as about.toml names it. A crate
# missing from Cargo.lock, an absolute path outside the registry, and a mark
# either pattern leaves behind are errors.
crates_text() {
  python3 -I - "$crates" Cargo.lock <<'EOF'
import re, sys

text = open(sys.argv[1], encoding="utf-8").read()
lock = open(sys.argv[2], encoding="utf-8").read()
sums = {
    (name, version): checksum
    for name, version, checksum in re.findall(
        r'^name = "(.+)"\nversion = "(.+)"\nsource = ".+"\nchecksum = "([0-9a-f]{64})"$',
        lock,
        re.M,
    )
}


def source(mark):
    path = mark[1]
    if not path.startswith("/"):
        return path
    packaged = re.match(r".*/registry/src/[^/]+/(.+)$", path)
    if packaged is None:
        sys.exit(f"error: {path} is outside cargo's registry; THIRD-PARTY-NOTICES.txt is unchanged")
    return packaged[1]


text = re.sub(r"LOCK_SHA256\((\S+) (\S+)\)", lambda m: sums[(m[1], m[2])], text)
text = re.sub(r"SOURCE_PATH\((\S+)\)", source, text)
for mark in ("LOCK_SHA256(", "SOURCE_PATH("):
    if mark in text:
        line = next(line for line in text.splitlines() if mark in line)
        sys.exit(f"error: a {mark}...) mark is left unreplaced in {line!r}; THIRD-PARTY-NOTICES.txt is unchanged")
print(text, end="")
EOF
}

rule="================================================================================"
heading() { printf '%s\n%s\n%s\n\n' "$rule" "$1" "$rule"; }

{
  echo "Third-party notices for fermix-iroh"
  echo
  echo "Every fermix-iroh release binary (aarch64-apple-darwin, x86_64-apple-darwin,"
  echo "aarch64-unknown-linux-musl, x86_64-unknown-linux-musl) is built from the"
  echo "software below, under the licences below. notices/generate.sh writes this"
  echo "file; it is not edited by hand."
  echo
  heading "fermix-iroh"
  cat LICENSE
  echo
  heading "The Rust standard library (Rust $toolchain), in every binary"
  echo "Licensed under MIT OR Apache-2.0. The Rust project's notice for it follows,"
  echo "as the toolchain ships it (share/doc/rust/COPYRIGHT-library.html)."
  echo
  std_text
  echo
  heading "musl libc $musl, in the Linux binaries only"
  echo "The Linux binaries are statically linked with the musl that Rust $toolchain"
  echo "bundles for its *-linux-musl targets. musl's COPYRIGHT file follows."
  echo
  cat "notices/musl-$musl-COPYRIGHT"
  echo
  heading "LLVM $llvm: libunwind and compiler-rt, in the Linux binaries only"
  echo "The Linux binaries also link LLVM's libunwind, which unwinds the stack for"
  echo "panics and backtraces, and compiler-rt's crtbegin and crtend objects, which"
  echo "Rust $toolchain builds from LLVM $llvm for its *-linux-musl targets. The aarch64"
  echo "binary also carries compiler-rt's outline atomics (lse.S) and CPU feature"
  echo "check (cpu_model/aarch64.c), which the standard library builds into"
  echo "compiler_builtins. Both are licensed under Apache-2.0 WITH LLVM-exception;"
  echo "the LICENSE.TXT of each follows."
  echo
  for component in libunwind compiler-rt; do
    printf '%s\n%s/LICENSE.TXT\n\n' "${rule//=/-}" "$component"
    cat "notices/llvm-$llvm-$component-LICENSE.TXT"
    echo
  done
  crates_text
} >"$out"
cat "$out" >THIRD-PARTY-NOTICES.txt
