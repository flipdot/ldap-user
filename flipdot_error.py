class Error(Exception):
    pass


class FrontendError(Error):

    def __init__(self, message):
        self.message = message
