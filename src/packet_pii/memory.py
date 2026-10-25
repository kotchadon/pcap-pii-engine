"""Process RSS readings, not physical footprint or an OS memory reservation.

Mach layout follows Apple's xnu/osfmk/mach/task_info.h (pack4,
MACH_TASK_BASIC_INFO=20). Explicit fixed-width types apply to arm64/x86_64.
"""
import ctypes
from functools import lru_cache
import resource
import sys


class _TimeValue(ctypes.Structure):
    _pack_=4
    _fields_=[('seconds',ctypes.c_int32),('microseconds',ctypes.c_int32)]


class _MachTaskBasicInfo(ctypes.Structure):
    _pack_=4
    _fields_=[('virtual_size',ctypes.c_uint64),('resident_size',ctypes.c_uint64),
              ('resident_size_max',ctypes.c_uint64),('user_time',_TimeValue),
              ('system_time',_TimeValue),('policy',ctypes.c_int32),('suspend_count',ctypes.c_int32)]


@lru_cache(maxsize=1)
def _mach_api():
    library=ctypes.CDLL('/usr/lib/libSystem.B.dylib')
    function=library.task_info
    function.argtypes=[ctypes.c_uint32,ctypes.c_uint32,ctypes.POINTER(ctypes.c_int32),
                       ctypes.POINTER(ctypes.c_uint32)]
    function.restype=ctypes.c_int32
    task=ctypes.c_uint32.in_dll(library,'mach_task_self_').value
    return library,function,task  # retain the loaded library along with function


def _read_mach_rss(function,task):
    info=_MachTaskBasicInfo();count=ctypes.c_uint32(ctypes.sizeof(info)//4)
    result=function(task,20,ctypes.cast(ctypes.byref(info),ctypes.POINTER(ctypes.c_int32)),ctypes.byref(count))
    if result!=0 or count.value!=12 or info.resident_size<=0:
        return None
    return int(info.resident_size)


def current_rss_bytes():
    """Return current resident bytes, or None on unsupported/invalid readings."""
    try:
        if sys.platform=='darwin':
            _,function,task=_mach_api()
            return _read_mach_rss(function,task)
        if sys.platform.startswith('linux'):
            with open('/proc/self/statm','rb') as file:
                pages=int(file.read(256).split()[1])
            return pages*resource.getpagesize() if pages>0 else None
    except (OSError,ValueError,IndexError,AttributeError,TypeError):
        pass
    return None


def peak_rss_bytes():
    """Process-lifetime high water: bytes on Darwin; KiB on Linux."""
    value=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(value if sys.platform=='darwin' else value*1024)
