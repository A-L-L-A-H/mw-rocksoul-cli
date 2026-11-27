#!/usr/bin/env bash
set -euo pipefail

# Cross-platform 1-line installer for rocksoul & mw-ww-cli with SHA-256 verification.
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/A-L-L-A-H/mw-rocksoul-cli/main/scripts/install.sh | bash
# Optional env vars:
#   ROCKSOUL_VERSION=v0.1.0 | latest
#   MW_WW_VERSION=v0.1.0 | latest
#   ROCKSOUL_REPO=A-L-L-A-H/mw-rocksoul-cli
#   MW_WW_REPO=A-L-L-A-H/mw-ww
#   ROCKSOUL_BASE_URL / MW_WW_BASE_URL (override release download base URL)
#   INSTALL_DIR=$HOME/.local/bin

ROCKSOUL_REPO="${ROCKSOUL_REPO:-A-L-L-A-H/mw-rocksoul-cli}"
MW_WW_REPO="${MW_WW_REPO:-A-L-L-A-H/mw-ww}"
ROCKSOUL_VERSION="${ROCKSOUL_VERSION:-latest}"
MW_WW_VERSION="${MW_WW_VERSION:-latest}"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"
INSTALL_WW=1

while [ "$#" -gt 0 ]; do
  case "$1" in
    --prefix|--dir)
      shift
      INSTALL_DIR="${1:?missing directory after --dir}"
      ;;
    --version)
      shift
      ROCKSOUL_VERSION="${1:?missing version after --version}"
      ;;
    --no-ww)
      INSTALL_WW=0
      ;;
    -h|--help)
      cat <<'EOF'
Rocksoul & mw-ww-cli installer

Options:
  --dir <path>       Target install directory (default: ~/.local/bin)
  --version <tag>    Rocksoul release tag (default: latest)
  --no-ww            Skip installing mw-ww-cli
EOF
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      exit 2
      ;;
  esac
  shift
done

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

detect_os() {
  local raw
  raw="$(uname -s 2>/dev/null || echo unknown)"
  case "$raw" in
    Linux*) echo "linux" ;;
    Darwin*) echo "darwin" ;;
    MINGW*|MSYS*|CYGWIN*|Windows_NT*) echo "windows" ;;
    *)
      echo "unsupported OS: $raw" >&2
      exit 1
      ;;
  esac
}

detect_arch() {
  local raw
  raw="$(uname -m 2>/dev/null || echo unknown)"
  case "$raw" in
    x86_64|amd64) echo "amd64" ;;
    arm64|aarch64) echo "arm64" ;;
    *)
      echo "unsupported architecture: $raw" >&2
      exit 1
      ;;
  esac
}

http_get() {
  local url="$1"
  local dest="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 3 --connect-timeout 15 -o "$dest" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$dest" "$url"
  else
    echo "error: curl or wget is required" >&2
    exit 1
  fi
}

sha256_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print tolower($1)}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print tolower($1)}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$file" | awk '{print tolower($NF)}'
  else
    echo "error: sha256sum, shasum, or openssl is required for SHA-256 verification" >&2
    exit 1
  fi
}

verify_sha256() {
  local artifact_path="$1"
  local artifact_name="$2"
  local checksums_file="$3"

  local expected=""
  expected="$(awk -v name="$artifact_name" '
    {
      gsub(/^\*/, "", $2);
      sub(/^\.\//, "", $2);
      if ($2 == name) { print tolower($1); exit }
    }
  ' "$checksums_file")"

  if [ -z "$expected" ]; then
    echo "error: checksum entry for $artifact_name not found in checksums.txt" >&2
    return 1
  fi

  local actual
  actual="$(sha256_file "$artifact_path")"
  if [ "$actual" != "$expected" ]; then
    echo "error: SHA-256 mismatch for $artifact_name (expected=$expected actual=$actual)" >&2
    return 1
  fi
  echo "verified SHA-256 for $artifact_name ($actual)"
}

resolve_base_url() {
  local repo="$1"
  local version="$2"
  local override="$3"
  if [ -n "$override" ]; then
    echo "${override%/}"
    return
  fi
  if [ "$version" = "latest" ]; then
    echo "https://github.com/${repo}/releases/latest/download"
  else
    echo "https://github.com/${repo}/releases/download/${version}"
  fi
}

extract_binary() {
  local archive="$1"
  local bin_name="$2"
  local out_dir="$3"
  case "$archive" in
    *.zip)
      if command -v unzip >/dev/null 2>&1; then
        unzip -qo "$archive" -d "$out_dir"
      elif command -v bsdtar >/dev/null 2>&1; then
        bsdtar -xf "$archive" -C "$out_dir"
      else
        echo "error: unzip or bsdtar is required to extract $archive" >&2
        return 1
      fi
      ;;
    *.tar.gz|*.tgz)
      tar -xzf "$archive" -C "$out_dir"
      ;;
    *)
      cp "$archive" "$out_dir/$bin_name"
      ;;
  esac
}

install_release_binary() {
  local tool="$1"
  local repo="$2"
  local version="$3"
  local base_override="$4"
  local os="$5"
  local arch="$6"
  local ext="$7"

  local base_url
  base_url="$(resolve_base_url "$repo" "$version" "$base_override")"
  local checksums_path="${TMP_DIR}/${tool}-checksums.txt"
  if ! http_get "${base_url}/checksums.txt" "$checksums_path"; then
    echo "error: failed to download checksums.txt from ${base_url}/checksums.txt" >&2
    return 1
  fi

  local candidate_bin="${tool}-${os}-${arch}${ext}"
  local candidate_zip=""
  if [ "$version" != "latest" ]; then
    local clean_ver="${version#v}"
    candidate_zip="${tool}_${clean_ver}_${os}_${arch}.zip"
  fi

  local chosen=""
  for cand in "$candidate_bin" "$candidate_zip" "${tool}_${os}_${arch}.zip" "${tool}-${os}-${arch}.tar.gz"; do
    if [ -n "$cand" ] && awk -v name="$cand" '{ gsub(/^\*/, "", $2); sub(/^\.\//, "", $2); if ($2 == name) found=1 } END { exit !found }' "$checksums_path"; then
      chosen="$cand"
      break
    fi
  done

  if [ -z "$chosen" ]; then
    echo "error: no matching artifact for ${tool} (${os}/${arch}) in checksums.txt" >&2
    return 1
  fi

  local artifact_path="${TMP_DIR}/${chosen}"
  http_get "${base_url}/${chosen}" "$artifact_path"
  verify_sha256 "$artifact_path" "$chosen" "$checksums_path"

  local stage_dir="${TMP_DIR}/stage-${tool}"
  mkdir -p "$stage_dir"
  local target_name="${tool}${ext}"
  extract_binary "$artifact_path" "$target_name" "$stage_dir"

  local found_bin=""
  if [ -f "${stage_dir}/${target_name}" ]; then
    found_bin="${stage_dir}/${target_name}"
  else
    found_bin="$(find "$stage_dir" -type f -name "$target_name" | head -n 1 || true)"
  fi
  if [ -z "$found_bin" ]; then
    echo "error: binary $target_name not found after extracting $chosen" >&2
    return 1
  fi

  mkdir -p "$INSTALL_DIR"
  install -m 0755 "$found_bin" "${INSTALL_DIR}/${target_name}" 2>/dev/null || {
    cp "$found_bin" "${INSTALL_DIR}/${target_name}"
    chmod +x "${INSTALL_DIR}/${target_name}"
  }
  echo "installed ${target_name} -> ${INSTALL_DIR}/${target_name}"
}

OS="$(detect_os)"
ARCH="$(detect_arch)"
EXT=""
if [ "$OS" = "windows" ]; then
  EXT=".exe"
fi

install_release_binary "rocksoul" "$ROCKSOUL_REPO" "$ROCKSOUL_VERSION" "${ROCKSOUL_BASE_URL:-}" "$OS" "$ARCH" "$EXT"
if [ "$INSTALL_WW" -eq 1 ]; then
  install_release_binary "mw-ww-cli" "$MW_WW_REPO" "$MW_WW_VERSION" "${MW_WW_BASE_URL:-}" "$OS" "$ARCH" "$EXT"
fi

case ":${PATH}:" in
  *":${INSTALL_DIR}:"*) ;;
  *)
    echo "Note: add ${INSTALL_DIR} to your PATH:"
    echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
    ;;
esac
