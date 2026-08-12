# ──────────────────────────────────────────────────────────────────────────────
# BundleStatic.cmake
#
# Merges mpt-crypto's own static archive together with its static dependencies
# (secp256k1 and OpenSSL's libcrypto) into ONE self-contained static archive.
#
# Why: a plain `libmpt-crypto.a` contains only mpt-crypto's object files — its
# secp256k1 / OpenSSL dependencies live in separate archives. Linking it alone
# produces a wall of unresolved symbols. The shared library avoids this by
# folding those deps IN at link time; this script does the same for the static
# archive so a consumer (e.g. the mpt-crypto-sys Rust crate) can statically link
# a single file and get a self-contained binary.
#
# Symbol visibility: on ELF/Linux the OpenSSL symbols are hidden (localized) so
# the archive can be linked into a program that ALSO links a *different* libcrypto
# — e.g. a Rust binary whose TLS stack (native-tls) uses the system OpenSSL —
# without the two copies colliding at link or clashing at runtime. secp256k1 and
# mpt-crypto's own API stay global, because the published bindings call straight
# into them (`secp256k1_ec_pubkey_create`, `mpt_*`, …). There is no secp256k1
# collision with a Rust consumer: `secp256k1-sys` renames its symbols to
# `rustsecp256k1_v0_*`, a disjoint namespace.
#
# macOS and Windows skip the hiding step: their DEFAULT TLS backends (Secure
# Transport / SChannel) do not link OpenSSL, so a typical consumer never ends up
# with two libcrypto copies, and Windows static-lib symbols are not exported
# anyway. CAVEAT: a consumer that EXPLICITLY links a different OpenSSL (e.g.
# openssl-sys / the Python `cryptography` wheel) and statically co-links this
# bundle on macOS could still hit two-copy interposition; such a consumer should
# use the shared library, or a macOS-hiding variant would be needed.
#
# Invoked in CMake script mode:
#   cmake -DMPT_LIB=<libmpt-crypto.a> -DSECP_LIB=<libsecp256k1.a> \
#         -DCRYPTO_LIB=<libcrypto.a>  -DOUT_LIB=<out> -DTARGET_OS=<CMAKE_SYSTEM_NAME> \
#         -P cmake/BundleStatic.cmake
# ──────────────────────────────────────────────────────────────────────────────

cmake_minimum_required(VERSION 3.16)

foreach(
    _var
    MPT_LIB
    SECP_LIB
    CRYPTO_LIB
    OUT_LIB
    TARGET_OS
)
    if(NOT DEFINED ${_var})
        message(FATAL_ERROR "BundleStatic: -D${_var}=... is required")
    endif()
endforeach()
# Inputs must exist; OUT_LIB is the product and TARGET_OS is a string.
foreach(_var MPT_LIB SECP_LIB CRYPTO_LIB)
    if(NOT EXISTS "${${_var}}")
        message(FATAL_ERROR "BundleStatic: ${_var} does not exist: ${${_var}}")
    endif()
endforeach()

get_filename_component(_work "${OUT_LIB}" DIRECTORY)
file(MAKE_DIRECTORY "${_work}")
file(REMOVE "${OUT_LIB}")

# ── macOS: libtool merges archives into one self-contained static lib ─────────
if(TARGET_OS STREQUAL "Darwin")
    find_program(LIBTOOL_EXE libtool REQUIRED)
    execute_process(
        COMMAND
            "${LIBTOOL_EXE}" -static -o "${OUT_LIB}" "${MPT_LIB}" "${SECP_LIB}"
            "${CRYPTO_LIB}"
        RESULT_VARIABLE _rc
    )
    if(_rc)
        message(FATAL_ERROR "BundleStatic: libtool merge failed (${_rc})")
    endif()

    # ── Windows: lib.exe merges .lib archives ────────────────────────────────────
elseif(TARGET_OS STREQUAL "Windows")
    find_program(LIB_EXE lib REQUIRED)
    execute_process(
        COMMAND
            "${LIB_EXE}" /NOLOGO "/OUT:${OUT_LIB}" "${MPT_LIB}" "${SECP_LIB}"
            "${CRYPTO_LIB}"
        RESULT_VARIABLE _rc
    )
    if(_rc)
        message(FATAL_ERROR "BundleStatic: lib.exe merge failed (${_rc})")
    endif()

    # ── ELF (Linux, incl. s390x): merge + hide OpenSSL symbols ───────────────────
else()
    find_program(LD_EXE ld REQUIRED)
    find_program(OBJCOPY_EXE objcopy REQUIRED)
    find_program(AR_EXE ar REQUIRED)
    find_program(NM_EXE nm REQUIRED)

    # 1. Collect the symbols to KEEP global: mpt-crypto's own API + secp256k1's
    #    public API. Everything else (OpenSSL, and any private helpers) is made
    #    local in step 3.
    #
    #    WARNING — secp256k1 stays GLOBAL by design: the published Rust/Python
    #    bindings call stock secp256k1_* through this archive. That is safe for
    #    those consumers only because they don't co-link a *stock* secp256k1
    #    (the Rust `secp256k1` crate renames its symbols to `rustsecp256k1_v0_*`;
    #    CPython doesn't use libsecp256k1). Do NOT statically co-link this bundle
    #    with an unrenamed secp256k1 (e.g. rippled) — the duplicated secp256k1_*
    #    symbols would collide. Such a consumer should use the SHARED library, or
    #    this bundle would need a variant that also hides secp256k1.
    set(_keep_syms "")
    foreach(_lib "${MPT_LIB}" "${SECP_LIB}")
        execute_process(
            COMMAND "${NM_EXE}" -g --defined-only "${_lib}"
            OUTPUT_VARIABLE _nm_out
            RESULT_VARIABLE _rc
        )
        if(_rc)
            message(FATAL_ERROR "BundleStatic: nm failed on ${_lib} (${_rc})")
        endif()
        string(REGEX MATCHALL "[^\n]+" _lines "${_nm_out}")
        foreach(_line ${_lines})
            # e.g. "0000000000000010 T secp256k1_ec_pubkey_create"
            if(_line MATCHES "^[0-9A-Fa-f]+ +[A-Za-z] +([A-Za-z0-9_.$]+)$")
                string(APPEND _keep_syms "${CMAKE_MATCH_1}\n")
            endif()
        endforeach()
    endforeach()
    if(_keep_syms STREQUAL "")
        message(
            FATAL_ERROR
            "BundleStatic: no global symbols found to keep — refusing to hide everything"
        )
    endif()
    set(_keep_file "${_work}/keep-global.txt")
    file(WRITE "${_keep_file}" "${_keep_syms}")

    # 2. Partial-link every member of all three archives into ONE relocatable
    #    object. This binds all intra-archive references (mpt-crypto → OpenSSL,
    #    secp256k1 internals, …) up front, so localizing OpenSSL in step 3 can
    #    never break mpt-crypto's own use of it. --whole-archive forces every
    #    member in (not just those resolving an already-undefined symbol).
    #    -d (--define-common) allocates COMMON symbols (e.g. OpenSSL's x86
    #    OPENSSL_ia32cap_P) into .bss as defined symbols. Without it they stay
    #    SHN_COMMON, which objcopy cannot localize in step 3 — so an OpenSSL
    #    common symbol would leak out globally.
    set(_combined "${_work}/mpt-crypto-combined.o")
    execute_process(
        COMMAND
            "${LD_EXE}" -r -d -o "${_combined}" --whole-archive "${MPT_LIB}"
            "${SECP_LIB}" "${CRYPTO_LIB}" --no-whole-archive
        RESULT_VARIABLE _rc
    )
    if(_rc)
        message(FATAL_ERROR "BundleStatic: ld -r partial link failed (${_rc})")
    endif()

    # 3. Demote every global symbol except the kept API to local — hides OpenSSL.
    execute_process(
        COMMAND
            "${OBJCOPY_EXE}" "--keep-global-symbols=${_keep_file}"
            "${_combined}"
        RESULT_VARIABLE _rc
    )
    if(_rc)
        message(FATAL_ERROR "BundleStatic: objcopy symbol hide failed (${_rc})")
    endif()

    # 4. Wrap the single relocatable object back into an archive.
    execute_process(
        COMMAND "${AR_EXE}" qcs "${OUT_LIB}" "${_combined}"
        RESULT_VARIABLE _rc
    )
    if(_rc)
        message(FATAL_ERROR "BundleStatic: ar failed (${_rc})")
    endif()
    file(REMOVE "${_combined}")
endif()

message(STATUS "BundleStatic: wrote self-contained archive ${OUT_LIB}")
