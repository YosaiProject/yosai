"""
The following classes are related to apache shiro concurrency.
I have no interest in implementing concurrency of any kind 
on day one, except for Session validation.  The non-concurrenty Yosai 
will serve as a benchmark that will be improved on in subsequent releases
through asyncio, multithreading, or whatever.  Any calls to the following
objects will be either removed or revised for non-concurrent processing.
"""
class Callable(object):
    pass


class Runnable(object):
    pass


class SubjectCallable(object):
    pass


class SubjectRunnable(object):
    pass


class Thread(object):
    pass

