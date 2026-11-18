from .base import Adapter


class GenericAdapter(Adapter):
    name = "generic"
    description = ("any executable; provides L3 (SRT) and L4 (Linux permissions) only. "
                   "L1/L2 are NOT_APPLICABLE, never faked")
