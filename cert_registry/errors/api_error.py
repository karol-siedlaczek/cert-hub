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
        detail: str | None = None,
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
        detail: str | None = None
    ) -> None:
        super().__init__(400, msg=msg, detail=detail)

