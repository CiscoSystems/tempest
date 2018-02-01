

class ASRTestException(Exception):

    def __init__(self, message):
        super(ASRTestException, self).__init__(message)


class NATNotFoundException(ASRTestException):

    def __init__(self, message):
        super(NATNotFoundException, self).__init__(message)


class IncorrectNATMappingException(ASRTestException):

    def __init__(self, message):
        super(IncorrectNATMappingException, self).__init__(message)


class NetconfErrorException(ASRTestException):

    def __init__(self, message):
        super(NetconfErrorException, self).__init__(message)


class ConfigSizeException(ASRTestException):

    def __init__(self, message):
        super(ConfigSizeException, self).__init__(message)


class StandbyGroupMismatchException(ASRTestException):

    def __init__(self, message):
        super(StandbyGroupMismatchException, self).__init__(message)


class StandbyVirtualIpException(ASRTestException):

    def __init__(self, message):
        super(StandbyVirtualIpException, self).__init__(message)


class StandbyStateException(ASRTestException):

    def __init__(self, message):
        super(StandbyStateException, self).__init__(message)


class StandbyPriorityException(ASRTestException):

    def __init__(self, message):
        super(StandbyPriorityException, self).__init__(message)


class ShowOutputParserException(Exception):

    def __init__(self, message):
        super(ShowOutputParserException, self).__init__(message)


class NoRedundantASRException(Exception):

    def __init__(self, message):
        super(NoRedundantASRException, self).__init__(message)


class VRFNotConfiguredException(Exception):

    def __init__(self, message):
        super(VRFNotConfiguredException, self).__init__(message)


class ASRTimeoutException(Exception):

    def __init__(self, message):
        super(ASRTimeoutException, self).__init__(message)


class NATPoolNotConfiguredException(Exception):

    def __init__(self, message):
        super(NATPoolNotConfiguredException, self).__init__(message)


class NoASRHaRouterFound(Exception):

    def __init__(self, message):
        super(NoASRHaRouterFound, self).__init__(message)
