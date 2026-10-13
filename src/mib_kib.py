KIB = 1024
MIB = 1024 * KIB
GIB = 1024 * MIB
TIB = 1024 * GIB

def mib_kib(size):
    if size >= TIB:
        return "{:.2f} TiB".format(size / TIB)
    elif size >= GIB:
        return "{:.2f} GiB".format(size / GIB)
    elif size >= MIB:
        return "{:.2f} MiB".format(size / MIB)
    elif size >= KIB:
        return "{:.2f} KiB".format(size / KIB)
    else:
        return "{} B".format(size)
    
    