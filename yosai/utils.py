import inspect


def myself(self):
    return inspect.stack()[1][3]

