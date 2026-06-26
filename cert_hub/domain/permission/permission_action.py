from enum import Enum

class PermissionAction(Enum):
    ANY = "*"
    READ = "read"
    ISSUE = "issue"
    RENEW = "renew"
    STATUS = "status"
    REVOKE = "revoke"
    RELOAD = "reload"

    @classmethod
    def values(cls) -> list[str]:
        return [item.value for item in cls]
