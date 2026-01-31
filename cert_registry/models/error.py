class ConfigError(RuntimeError):
    pass


class AuthTokenError(RuntimeError):
    pass


class AuthIpNotAllowedError(RuntimeError):
    pass


class AuthMissingPermission(RuntimeError):
    pass
