class AuthError(Exception):
    code: int
    msg: str
    detail: str
    
    def __init__(
        self, 
        code: int, 
        msg: str, 
        detail: str | None = None
    ) -> None:
        self.code = code
        self.msg = msg
        self.detail = detail
        super().__init__(f"{msg}: {detail}")


class AuthTokenMissingError(AuthError):
    def __init__(self, msg: str) -> None:
        super().__init__(401, "Authorization is required", msg)


class AuthFailedError(AuthError):
    def __init__(self, msg: str) -> None:
        super().__init__(401, "Authorization failed", msg)


class AuthIpNotAllowedError(AuthError):
    def __init__(self, ip_addr: str) -> None:
        super().__init__(403, "Access denied", f"Request from IP address '{ip_addr}' is not permitted for this identity")
