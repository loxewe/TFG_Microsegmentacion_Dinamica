class AdapterError(RuntimeError):
    """Base error for failures that can be presented by an orchestrator."""


class AdapterAuthenticationError(AdapterError):
    pass


class AdapterProtocolError(AdapterError):
    pass


class AdapterUnsupportedOperation(AdapterError):
    pass


class AdapterVerificationError(AdapterError):
    pass
