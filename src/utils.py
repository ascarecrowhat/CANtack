class Logger(object):
    verbose=None

    def __init__(self, verbose=True):
        self.verbose = verbose

    def print(self, s):
        if self.verbose:
            print(s)