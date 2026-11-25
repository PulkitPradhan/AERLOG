"""Run the smoke test with Unix-domain sockets only, preserving file ownership."""
import ctypes
import errno
import os
import socket
import sys


class ArgumentComparison(ctypes.Structure):
    _fields_ = [
        ("argument", ctypes.c_uint),
        ("operation", ctypes.c_int),
        ("value", ctypes.c_uint64),
        ("mask", ctypes.c_uint64),
    ]


def main() -> None:
    library = ctypes.CDLL("libseccomp.so.2")
    library.seccomp_init.argtypes = [ctypes.c_uint32]
    library.seccomp_init.restype = ctypes.c_void_p
    library.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    library.seccomp_rule_add_array.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint,
        ctypes.POINTER(ArgumentComparison),
    ]
    library.seccomp_load.argtypes = [ctypes.c_void_p]
    library.seccomp_release.argtypes = [ctypes.c_void_p]

    allow = 0x7FFF0000  # SCMP_ACT_ALLOW
    deny = 0x00050000 | errno.EPERM  # SCMP_ACT_ERRNO(EPERM)
    not_equal = 1  # SCMP_CMP_NE
    comparison = ArgumentComparison(0, not_equal, socket.AF_UNIX, 0)
    context = library.seccomp_init(allow)
    if not context:
        raise RuntimeError("Could not initialize the offline smoke-test filter.")
    try:
        for name in (b"socket", b"socketpair"):
            syscall = library.seccomp_syscall_resolve_name(name)
            if library.seccomp_rule_add_array(context, deny, syscall, 1, ctypes.byref(comparison)):
                raise RuntimeError(f"Could not add the offline filter for {name!r}.")
        if library.seccomp_load(context):
            raise RuntimeError("Could not enable the offline smoke-test filter.")
    finally:
        library.seccomp_release(context)

    os.execvp(sys.argv[1], sys.argv[1:])


if __name__ == "__main__":
    main()
