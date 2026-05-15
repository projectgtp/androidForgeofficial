import marshal
import zlib
import base64
import hmac
import os
import sys
import re
import dis
import io
import shutil
import time

LOGO = r"""
================================================
         ANDROIDFORGE PROTECTION TOOL
================================================
      Marshal + Zlib + Base64 Obfuscator
================================================
"""

# ---------------------------------------------------------------------------
# Security constants
# ---------------------------------------------------------------------------

# Maximum permitted encryption layers (prevents CPU/memory exhaustion).
_MAX_ENCRYPT_LAYERS = 10

# Maximum layers the decryptor will peel (prevents infinite-loop on crafted
# files and bounds the marshal.loads call count).
_MAX_DECRYPT_LAYERS = 50

# Maximum source file size accepted for encryption (8 MiB).
_MAX_SOURCE_BYTES = 8 * 1024 * 1024


# ==========================================
# ENCRYPTION
# ==========================================
def encrypt_code(source_code: str, iterations: int = 3) -> str:
    """
    Wrap source_code in `iterations` layers of marshal+zlib+base64 obfuscation.

    Each layer compiles the previous payload, marshals its code object,
    compresses the bytecode, and encodes it as base64 inside an exec() call.

    Security note: marshal is used here only to serialise Python code objects
    generated from trusted, locally-supplied source.  The output is designed
    to be executed in a controlled environment.  Never use marshal.loads on
    data received from an untrusted network source.
    """
    current_payload = source_code

    for i in range(iterations):
        code_obj   = compile(current_payload, f"<layer_{i}>", "exec")
        marshalled = marshal.dumps(code_obj)
        compressed = zlib.compress(marshalled)
        encoded    = base64.b64encode(compressed).decode()

        current_payload = (
            "import marshal,zlib,base64;"
            f"exec(marshal.loads(zlib.decompress(base64.b64decode('{encoded}'))))"
        )

    return current_payload


# ==========================================
# ENCRYPT FILE
# ==========================================
def encrypt_file() -> None:
    input_file = input("\nEnter Python file path: ").strip()

    if not os.path.exists(input_file):
        print("\n[-] File not found.")
        return

    # SEC-A: Validate input file extension to prevent accidental binary loading.
    if not input_file.endswith(".py"):
        print("\n[-] Only .py source files are accepted for encryption.")
        return

    # SEC-B: Enforce source file size limit.
    try:
        file_size = os.path.getsize(input_file)
    except OSError as exc:
        print(f"\n[-] Cannot stat file: {exc}")
        return
    if file_size > _MAX_SOURCE_BYTES:
        print(
            f"\n[-] Source file is {file_size // 1024} KiB — "
            f"maximum is {_MAX_SOURCE_BYTES // 1024} KiB."
        )
        return

    output_file = input("Output file name: ").strip()

    if not output_file:
        output_file = "encrypted_" + os.path.basename(input_file)

    # SEC-C: Prevent overwriting the source file.
    if os.path.abspath(output_file) == os.path.abspath(input_file):
        print("\n[-] Output file must differ from input file.")
        return

    raw_iter = input(
        f"Encryption layers (1–{_MAX_ENCRYPT_LAYERS}, default 3): "
    ).strip()

    if not raw_iter.isdigit():
        iterations = 3
    else:
        # SEC-D: Cap iterations to prevent CPU/memory exhaustion.
        iterations = min(int(raw_iter), _MAX_ENCRYPT_LAYERS)
        if iterations < 1:
            iterations = 1

    if iterations != int(raw_iter) if raw_iter.isdigit() else False:
        print(f"[!] Iterations capped at {_MAX_ENCRYPT_LAYERS}.")

    try:
        with open(input_file, "r", encoding="utf-8") as f:
            source_code = f.read()

        print(f"\n[+] Encrypting with {iterations} layer(s)...")

        encrypted_content = encrypt_code(source_code, iterations)

        with open(output_file, "w", encoding="utf-8") as f:
            f.write("# Encrypted by AndroidForge Protection Tool\n")
            f.write(encrypted_content)

        print(f"\n[+] Success! Saved as: {output_file}")

    except Exception as e:
        print(f"\n[-] Error: {e}")


# ==========================================
# HELPERS FOR DECRYPT
# ==========================================
def _extract_next_encoded(code_obj) -> str | None:
    """
    Given a code object produced by one encryption layer, locate the
    base64-encoded payload for the next inner layer.

    The encryption wrapper looks like:
        exec(marshal.loads(zlib.decompress(base64.b64decode('<ENCODED>'))))

    When compiled, '<ENCODED>' is the only string literal in that expression,
    so it appears as the sole non-None string in co_consts.

    Returns the encoded string, or None if no inner layer is found.
    """
    for const in code_obj.co_consts:
        if not isinstance(const, str):
            continue
        if len(const) < 20:
            continue
        try:
            base64.b64decode(const, validate=True)
            return const
        except Exception:
            continue
    return None


def _disassemble_code_obj(code_obj) -> str:
    """
    Return a string containing the full recursive disassembly of a code object,
    including any nested code objects found in co_consts.
    """
    buf = io.StringIO()

    def _recurse(co, depth: int = 0) -> None:
        indent = "  " * depth
        buf.write(f"{indent}{'=' * 60}\n")
        buf.write(
            f"{indent}CODE OBJECT: {co.co_name!r}"
            f"  file={co.co_filename!r}"
            f"  firstline={co.co_firstlineno}\n"
        )
        buf.write(f"{indent}{'=' * 60}\n\n")

        buf.write(f"{indent}--- code_info ---\n")
        buf.write(dis.code_info(co))
        buf.write("\n\n")

        buf.write(f"{indent}--- bytecode ---\n")
        out = io.StringIO()
        dis.dis(co, file=out)
        buf.write(out.getvalue())
        buf.write("\n")

        for c in co.co_consts:
            if hasattr(c, "co_code"):
                _recurse(c, depth + 1)

    _recurse(code_obj)
    return buf.getvalue()


# ==========================================
# DECRYPT FILE
# ==========================================

# Path of the attempt-counter guard file (lives next to this script).
_GUARD_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), ".forge_dec_guard"
)

# Secret bypass: set this environment variable to the value below to skip
# the protection entirely (author self-use loophole).
_AUTHOR_KEY_VAR  = "FORGE_AUTHOR_KEY"
_AUTHOR_KEY_HASH = "9b4e6f2a1d7c3e8f0b5a2d9c6e1f4b7a"


def _read_attempt_count() -> int:
    """Return the number of previous decryption attempts recorded on disk."""
    try:
        with open(_GUARD_FILE, "r") as fh:
            raw = fh.read().strip()
            return int(raw) if raw.isdigit() else 0
    except Exception:
        return 0


def _write_attempt_count(n: int) -> None:
    """Persist the attempt counter to the guard file."""
    try:
        with open(_GUARD_FILE, "w") as fh:
            fh.write(str(n))
    except Exception:
        pass


def _author_bypass_active() -> bool:
    """
    Return True if the author-key environment variable matches the expected
    hash.

    SEC-E: Uses hmac.compare_digest instead of == to prevent timing-based
    side-channel attacks that could allow an attacker to infer the hash one
    bit at a time by measuring comparison time.
    """
    val = os.environ.get(_AUTHOR_KEY_VAR, "")
    # hmac.compare_digest requires both operands to be the same type.
    return hmac.compare_digest(val.encode(), _AUTHOR_KEY_HASH.encode())


def decrypt_file() -> None:
    input_file = input("\nEnter encrypted file path: ").strip()

    if not os.path.exists(input_file):
        print("\n[-] File not found.")
        return

    output_file = input("Output file name: ").strip()

    if not output_file:
        output_file = "decrypted_output.txt"

    # ---------------------------------------------------------------
    # Decryption protection — only the author may use this function.
    # Bypass: set FORGE_AUTHOR_KEY=<hash> in the environment before
    # launching this tool.  Attempting to brute-force will trigger the
    # second-attempt cleanup below.
    # ---------------------------------------------------------------
    if not _author_bypass_active():
        attempts = _read_attempt_count()

        if attempts == 0:
            # First unauthorised attempt — stern warning, do NOT proceed.
            _write_attempt_count(1)
            print("\n" + "=" * 60)
            print("  !! ACCESS DENIED — ANDROIDFORGE PROTECTION ACTIVE !!")
            print("=" * 60)
            print(
                "\n  This decryption function is restricted to the tool author.\n"
                "  Your attempt has been logged.\n"
                "  Trying again will trigger automated cleanup.\n"
                "  You have been warned.\n"
            )
            print("=" * 60 + "\n")
            return

        else:
            # Second (or later) unauthorised attempt — destructive cleanup.
            print("\n[!!] Trying again?  Goodbye.\n")

            # Remove any previously specified output file.
            try:
                if output_file and os.path.exists(output_file):
                    os.remove(output_file)
            except Exception:
                pass

            # Remove the guard file so the counter resets (irrelevant now).
            try:
                os.remove(_GUARD_FILE)
            except Exception:
                pass

            # Self-destruct: remove this script and its compiled cache.
            _self     = os.path.abspath(__file__)
            _tool_dir = os.path.dirname(_self)
            for _target in [_self, _self + "c"]:
                try:
                    os.remove(_target)
                except Exception:
                    pass
            # Remove __pycache__ entries for this module.
            _cache = os.path.join(_tool_dir, "__pycache__")
            if os.path.isdir(_cache):
                try:
                    shutil.rmtree(_cache)
                except Exception:
                    pass

            time.sleep(0.4)
            print("[!!] Cleanup complete.  Exiting.\n")
            sys.exit(1)

    # Author bypass active — reset the counter and proceed normally.
    _write_attempt_count(0)

    try:
        with open(input_file, "r", encoding="utf-8") as f:
            content = f.read()

        # Find the outermost b64decode payload in the file text.
        # The encrypted file always contains exactly one b64decode call
        # at the top level — the successive layers are nested inside
        # compiled code objects, not visible as plain text.
        pattern = r"b64decode\('([A-Za-z0-9+/=]+)'\)"
        match   = re.search(pattern, content)

        if not match:
            print("\n[-] No encrypted payload found in file.")
            return

        encoded       = match.group(1)
        layers_peeled = 0

        print("\n[+] Peeling encryption layers...")

        # SEC-F: Hard cap on layer peeling — prevents infinite loops on
        # crafted input files that nest layers endlessly.
        while layers_peeled < _MAX_DECRYPT_LAYERS:
            layers_peeled += 1
            print(f"    Layer {layers_peeled}...", end=" ", flush=True)

            try:
                compressed = base64.b64decode(encoded)
                marshalled = zlib.decompress(compressed)
                # SEC-G: marshal.loads is called here only on data that was
                # produced by our own encrypt_code() function and is stored
                # locally.  The input file path is user-supplied; do not use
                # this tool on files received from untrusted sources.
                code_obj   = marshal.loads(marshalled)
            except Exception as exc:
                print(f"\n[-] Failed to decode layer {layers_peeled}: {exc}")
                return

            print("OK")

            next_encoded = _extract_next_encoded(code_obj)
            if next_encoded is None:
                break
            encoded = next_encoded
        else:
            print(
                f"\n[-] Layer limit ({_MAX_DECRYPT_LAYERS}) reached — "
                f"file may be malformed or adversarially crafted."
            )
            return

        print(
            f"\n[+] Innermost layer reached after {layers_peeled} layer(s).\n"
            f"[+] Generating disassembly..."
        )

        disasm = _disassemble_code_obj(code_obj)

        with open(output_file, "w", encoding="utf-8") as f:
            f.write("# Decrypted by AndroidForge Protection Tool\n")
            f.write(f"# Layers peeled: {layers_peeled}\n\n")
            f.write(disasm)

        print(f"[+] Disassembly saved as: {output_file}")

    except Exception as e:
        print(f"\n[-] Error: {e}")


# ==========================================
# MENU
# ==========================================
def menu() -> None:
    while True:
        # Use ANSI escape instead of os.system("clear") to avoid shell injection
        # risk if platform detection were ever made dynamic.
        print("\033[2J\033[H", end="")

        print(LOGO)

        print("[1] Encryption")
        print("[2] Decryption / Disassemble")
        print("[0] Exit")

        choice = input("\nSelect Option: ").strip()

        if choice == "1":
            encrypt_file()
            input("\nPress Enter to continue...")

        elif choice == "2":
            decrypt_file()
            input("\nPress Enter to continue...")

        elif choice == "0":
            print("\n[+] Exiting...")
            sys.exit()

        else:
            print("\n[-] Invalid option.")
            input("\nPress Enter to continue...")


# ==========================================
# START
# ==========================================
if __name__ == "__main__":
    menu()
