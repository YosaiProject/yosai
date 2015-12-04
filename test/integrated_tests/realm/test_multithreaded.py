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

perms = {DefaultPermission(domain={'domain1'}, action={'action1'}),
         DefaultPermission(domain={'domain2'}, action={'action1', 'action2'}),
         DefaultPermission(domain={'domain3'}, action={'action1', 'action2', 'action3'}, target={'target1'}),
         DefaultPermission(domain={'domain4'}, action={'action1', 'action2'}),
         DefaultPermission(domain={'domain4'}, action={'action3'}, target={'target1'}),
         DefaultPermission(wildcard_string='*:action5')}

roles = {SimpleRole(role_identifier='role1'), 
         SimpleRole(role_identifier='role2'), 
         SimpleRole(role_identifier='role3')}

authz_info = IndexedAuthorizationInfo(roles=roles, permissions=perms)

sm = SerializationManager()

reg = make_region().configure('yosai_dpcache.redis', 
                              expiration_time=3600, 
                              arguments={'url': '127.0.0.1'}, 
                              wrap=[(SerializationProxy, 
                                     sm.serialize, 
                                     sm.deserialize)])

def test_threaded_dogpile():

    lock = Lock()
    canary = []
    results = []

    def creator():
        ack = lock.acquire(False)
        canary.append(ack)
        time.sleep(.25)
        if ack:
            lock.release()
        return authz_info 

    def f():
        for x in range(5):
            results.append(reg.get_or_create("some key", creator, 100))
            time.sleep(.5)

    threads = [Thread(target=f) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # assert len(canary) > 2
    print('canary: ', canary)
    if not reg.backend.has_lock_timeout():
        assert False not in canary
    else:
        assert False in canary
    print('number of results: ', len(results))
    print('\nresults: ')
    pp.pprint(results)

test_threaded_dogpile()


"""
def test_threaded_get_multi():

    locks = dict((str(i), Lock()) for i in range(11))

    canary = collections.defaultdict(list)

    def creator(*keys):
        assert keys
        ack = [locks[key].acquire(False) for key in keys]

        # print(
        #        ("%s " % thread.get_ident()) + \
        #        ", ".join(sorted("%s=%s" % (key, acq)
        #                    for acq, key in zip(ack, keys)))
        #    )

        for acq, key in zip(ack, keys):
            canary[key].append(acq)

        time.sleep(.5)

        for acq, key in zip(ack, keys):
            if acq:
                locks[key].release()
        return ["some value %s" % k for k in keys]

    def f():
        for x in range(5):
            reg.get_or_create_multi(
                [str(random.randint(1, 10))
                    for i in range(random.randint(1, 5))],
                creator)
            time.sleep(.5)
    f()
    return
    threads = [Thread(target=f) for i in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sum([len(v) for v in canary.values()]) > 10
    for l in canary.values():
        assert False not in l
"""

