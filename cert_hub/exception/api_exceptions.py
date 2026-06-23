class ApiError(Exception):
    code: int
    msg: str
    detail: str
    level: str
    
    def __init__(
        self, 
        code: int,
        *,
        msg: str,
        detail: object | None = None,
        level: str = "warning"
    ) -> None:
        self.code = code
        self.msg = msg
        self.detail = detail
        self.level = level
        super().__init__(f"{msg}: {detail}")


class InvalidRequestError(ApiError):
    def __init__(
        self,
        msg: str,
        *,
        detail: object | None = None
    ) -> None:
        super().__init__(400, msg=msg, detail=detail)


class PermissionDenied(ApiError):
    def __init__(
        self,
        msg: str,
        *,
        detail: object | None = None
    ) -> None:
        super().__init__(403, msg=msg, detail=detail)


class ResourceNotFound(ApiError):
    def __init__(
        self,
        msg: str,
        *,
        detail: object | None = None
    ) -> None:
        super().__init__(404, msg=msg, detail=detail)
