import inspect


def who_am_i(self):
    return inspect.stack()[1][3]

