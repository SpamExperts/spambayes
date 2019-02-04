from future import standard_library
standard_library.install_aliases()
try:
    # New in Python 2.5
    from hashlib import md5
except ImportError:
    # Python 2.4
    from md5 import new as md5

try:
    import bsddb3
    bsddb = bsddb3
    del bsddb3
except ImportError:
    try:
        import bsddb
    except ImportError:
        bsddb = None

try:
    import dbm.gnu
except ImportError:
    gdbm = None

