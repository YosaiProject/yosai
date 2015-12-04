import time
from threading import Thread, Lock
import random
import collections
import pprint 

from yosai import DefaultPermission
from yosai import IndexedAuthorizationInfo
from yosai import SerializationManager
from yosai import SimpleRole

from yosai_dpcache.cache.region import make_region
from proxybackend import SerializationProxy

pp = pprint.PrettyPrinter(indent=1)

sm = SerializationManager()

def test_multithreaded_authz_dogpile(indexed_authz_info):

    lock = Lock()
    canary = []
    results = []

    def creator():
        ack = lock.acquire(False)
        canary.append(ack)
        time.sleep(.25)
        if ack:
            lock.release()
        return indexed_authz_info 

    def f():
        for x in range(5):
            results.append(reg.get_or_create("userid12345", creator, 100))
            time.sleep(.5)

    threads = [Thread(target=f) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    if not reg.backend.has_lock_timeout():
        assert False not in canary
    else:
        assert False in canary
    
    assert len(results) == 50
