"""Fail closed before secure evidence I/O on unsupported platforms.

Linux/Python 3.12 is the formal pilot execution platform. Windows supports
metadata inspection and the explicit refusal path, not secure execution.
"""

import errno
import os

try:
    import fcntl
except ImportError:
    fcntl = None


class PlatformUnsupported(OSError):
    def __init__(self):
        super().__init__(getattr(errno, "ENOTSUP", errno.EINVAL), "PLATFORM_UNSUPPORTED")


def secure_io_supported(*, locking=False):
    return (os.name == "posix"
            and all(getattr(os, name, 0) for name in ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK"))
            and os.open in getattr(os, "supports_dir_fd", ())
            and (not locking or fcntl is not None))


def require_secure_io(*, locking=False):
    if not secure_io_supported(locking=locking):
        raise PlatformUnsupported()


def unsupported_report():
    return {"state": "PLATFORM_UNSUPPORTED", "dispatchable": False,
            "formal_pilot_rows": 0, "new_model_requests": 0, "new_tool_executions": 0}
