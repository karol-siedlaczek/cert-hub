from enum import Enum

class CertType(str, Enum):
    ALL = "all"
    LETSENCRYPT = "letsencrypt"
    STATIC = "static"

    @classmethod
    def values(cls) -> list[str]:
        return [item.value for item in cls]
