class ApiError(Exception):
    code: int
    msg: str
    detail: str
    
    def __init__(
        self, 
        code: int,
        *,
        msg: str,
        detail: str | None = None
    ) -> None:
        self.code = code
        self.msg = msg
        self.detail = detail
        super().__init__(f"{msg}: {detail}")


class InvalidRequestError(ApiError):
    def __init__(
        self,
        msg: str,
        *,
        detail: str | None = None
    ) -> None:
        super().__init__(400, msg=msg, detail=detail)


