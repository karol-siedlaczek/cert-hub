from typing import Enum

class DomainEnum(Enum):
    @classmethod
    def values(cls) -> list[str]:
        return [item.value for item in cls]
