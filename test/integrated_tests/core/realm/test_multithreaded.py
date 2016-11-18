import time
from threading import Thread, Lock


def test_multithreaded_authz_dogpile(cache_handler, session):

    lock = Lock()
    canary = []
    results = []

    def create_func(arbitrary):
        nonlocal canary
        nonlocal lock
        ack = lock.acquire(False)
        canary.append(ack)
        time.sleep(.25)
        if ack:
            lock.release()
        return 'authz_info'

    def f():
        for x in range(5):
            results.append(cache_handler.get_or_create(domain='authz_info',
                                                       identifier='thedude',
                                                       creator_func=create_func,
                                                       creator=None))
            time.sleep(.5)

    threads = [Thread(target=f) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    if not cache_handler.cache_region.backend.has_lock_timeout():
        assert False not in canary
    else:
        assert False in canary

    assert len(results) == 50
