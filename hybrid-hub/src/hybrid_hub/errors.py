class HubError(Exception):
    """Base class for expected, fail-closed hub errors."""


class PolicyDenied(HubError):
    pass


class ValidationError(HubError):
    pass


class PathDenied(HubError):
    pass


class ConflictError(HubError):
    pass


class AdapterError(HubError):
    pass


class AuthorizationRequired(HubError):
    pass
