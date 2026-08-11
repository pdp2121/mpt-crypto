#!/usr/bin/env bash
# Build mpt-crypto as a STATIC library and bundle secp256k1 + OpenSSL's
# libcrypto into a single self-contained archive (see cmake/BundleStatic.cmake).
# Mirrors build-shared-lib.sh, but with `shared=False` + the bundle step, and a
# post-build self-containment / symbol-visibility verification.
set -euo pipefail

conan profile detect --force
conan remote add --index 0 --force xrplf https://conan.ripplex.io

CONAN_ARGS=(
  -of build-static
  --build=missing
  -s build_type=Release
  -o "&:shared=False"
  -o "&:tests=True"
  -o "secp256k1/*:shared=False"
  -o "openssl/*:shared=False"
  # Drop OpenSSL's optional zlib support: it makes libcrypto.a reference external
  # deflate/inflate, which would leak out of the "self-contained" archive and
  # force every consumer to also link -lz. mpt-crypto uses no compression.
  -o "openssl/*:no_zlib=True"
)
if [[ "${RUNNER_OS:-Linux}" != "Windows" ]]; then
  CONAN_ARGS+=(-o "secp256k1/*:fPIC=True" -o "openssl/*:fPIC=True")
fi
conan install . "${CONAN_ARGS[@]}"

# Conan's generator subfolder nests differently across versions/layouts; locate
# the toolchain rather than hardcoding a path.
TOOLCHAIN="$(find build-static -name conan_toolchain.cmake | head -1)"
[[ -n "$TOOLCHAIN" ]] || { echo "ERROR: conan_toolchain.cmake not found under build-static/"; exit 1; }

CMAKE_ARGS=(
  -B build-static
  -S .
  -DCMAKE_TOOLCHAIN_FILE:FILEPATH="${TOOLCHAIN}"
  -DMPT_CRYPTO_BUNDLE_STATIC=ON
)
if [[ "${RUNNER_OS:-Linux}" == "Windows" ]]; then
  CMAKE_ARGS+=(
    -G "Visual Studio 17 2022"
    -A x64
  )
else
  CMAKE_ARGS+=(
    -G Ninja
    -DCMAKE_BUILD_TYPE=Release
  )
fi
cmake "${CMAKE_ARGS[@]}"

cmake --build build-static --config Release

# Tests link against the (thin) static target, validating that the static build
# itself is sound.
pushd build-static > /dev/null
CTEST_ARGS=(--output-on-failure)
if [[ "${RUNNER_OS:-Linux}" == "Windows" ]]; then
  export PATH="$(pwd)/Release:${PATH}"
  CTEST_ARGS+=(-C Release)
fi
ctest "${CTEST_ARGS[@]}"
popd > /dev/null

# ── Verify the bundled archive is self-contained & correctly scoped ──────────
if [[ "${RUNNER_OS:-Linux}" == "Windows" ]]; then
  BUNDLED="build-static/mpt-crypto-bundled.lib"
else
  BUNDLED="build-static/libmpt-crypto-bundled.a"
fi
[[ -f "$BUNDLED" ]] || { echo "ERROR: bundled archive not produced at $BUNDLED"; exit 1; }
echo "Bundled archive: $BUNDLED ($(du -h "$BUNDLED" | cut -f1))"

# ── (1) Authoritative self-containment: link a tiny program against ONLY the
#        bundle + platform base libs (no -lcrypto/-lssl/-lsecp256k1/-lz). If any
#        dependency wasn't folded in, the link fails here. Then run it. ─────────
if [[ "${RUNNER_OS:-Linux}" != "Windows" ]]; then
  TESTDIR="$(mktemp -d)"
  cat > "${TESTDIR}/linktest.c" <<'EOF'
#include <stdint.h>
#include <stdio.h>
/* Declared directly so the test needs no dependency headers. */
int mpt_generate_keypair(uint8_t* out_privkey, uint8_t* out_pubkey);
int main(void) {
    uint8_t sk[32] = {0}, pk[33] = {0};
    int rc = mpt_generate_keypair(sk, pk);
    /* Compressed secp256k1 pubkeys start 0x02/0x03 — sanity-check it ran. */
    printf("mpt_generate_keypair rc=%d pk[0]=0x%02x\n", rc, pk[0]);
    return rc == 0 && (pk[0] == 0x02 || pk[0] == 0x03) ? 0 : 1;
}
EOF
  # Base system libs only — the same ones the shared lib leaves dynamic.
  if [[ "$(uname -s)" == "Darwin" ]]; then
    BASE_LIBS=(-lc++)
    CC_BIN="${CC:-clang}"
  else
    BASE_LIBS=(-lstdc++ -lpthread -ldl -lm)
    CC_BIN="${CC:-cc}"
  fi
  if ! "${CC_BIN}" "${TESTDIR}/linktest.c" "$BUNDLED" "${BASE_LIBS[@]}" -o "${TESTDIR}/linktest"; then
    echo "ERROR: bundled archive is NOT self-contained — link against it alone failed."
    exit 1
  fi
  "${TESTDIR}/linktest" || { echo "ERROR: linked program did not run cleanly."; exit 1; }
  echo "OK: links + runs standalone (self-contained)."
  rm -rf "${TESTDIR}"
fi

# ── (2) Symbol visibility (nm — skipped on Windows, which lacks it here) ──────
if command -v nm > /dev/null 2>&1 && [[ "${RUNNER_OS:-Linux}" != "Windows" ]]; then
  # (a) API present: mpt-crypto + secp256k1 public symbols must stay global.
  #     (macOS prefixes symbols with a leading underscore, hence _?.)
  for sym in mpt_encrypt_amount secp256k1_ec_pubkey_create; do
    found="$(nm -g --defined-only "$BUNDLED" 2>/dev/null | grep -E " _?${sym}\$" || true)"
    if [[ -z "$found" ]]; then
      echo "ERROR: expected global API symbol '$sym' is missing/hidden."
      exit 1
    fi
  done
  echo "OK: mpt-crypto + secp256k1 API symbols are global."

  # (b) OpenSSL hidden (ELF/Linux only — macOS keeps them, which is fine there).
  if [[ "$(uname -s)" == "Linux" ]]; then
    leaked="$(nm -g --defined-only "$BUNDLED" 2>/dev/null \
                | grep -E ' (EVP_[A-Za-z]|OPENSSL_[A-Za-z]|OSSL_)' || true)"
    if [[ -n "$leaked" ]]; then
      echo "ERROR: OpenSSL symbols are still global (should be hidden):"
      echo "$leaked" | head
      exit 1
    fi
    echo "OK: OpenSSL symbols are hidden (localized)."
  fi
fi

echo "Static bundle verification passed."
