class ConfigError(RuntimeError):
    pass


class AuthError(Exception):
    pass


class AuthTokenMissingError(AuthError):
    pass


class AuthFailedError(AuthError):
    pass
