import pytest
from unittest import mock
from yosai import (
    AbstractSessionStore,
    IllegalArgumentException,
    IllegalStateException,
    RandomSessionIDGenerator,
    UnknownSessionException,
    UUIDSessionIDGenerator,
)

from ..doubles import (
    MockCache,
)

from .doubles import (
    MockCachingSessionStore,
)

# -----------------------------------------------------------------------------
# AbstractSessionStore
# -----------------------------------------------------------------------------

@pytest.mark.parametrize('sessiongen', [UUIDSessionIDGenerator, 
                                        RandomSessionIDGenerator])
def test_asd_generate_session_id_succeeds(
        mock_abstract_session_store, sessiongen, monkeypatch):
    """
    unit tested:  generate_session_id

    test case:
    successfully generates a session_id (str)
    """
    masd = mock_abstract_session_store
    monkeypatch.setattr(masd, 'session_id_generator', sessiongen) 
    with mock.patch.object(sessiongen, 'generate_id') as mock_gen:
        mock_gen.return_value = 'sessionid1234'
        masd.generate_session_id(session='arbitrarysession')

def test_asd_generate_session_id_raises(mock_abstract_session_store):
    """
    unit tested:  generate_session_id

    test case:
    when a session_id generator isn't assigned to the ASD, an exception raises
    """
    masd = mock_abstract_session_store
    with mock.patch.object(RandomSessionIDGenerator, 'generate_id') as mock_gen:
        mock_gen.side_effect = AttributeError 
        with pytest.raises(IllegalStateException):
            masd.generate_session_id(session='arbitrarysession')

def test_asd_create_raises(mock_abstract_session_store, monkeypatch):
    """
    unit tested:  create

    test case:
    create calls verify_session_id, which will raise when session_id is None
    """
    masd = mock_abstract_session_store
    monkeypatch.setattr(masd, 'do_create', lambda x: None)
    with pytest.raises(IllegalStateException):
        masd.create(session='arbitrarysession')

def test_asd_create_succeeds(mock_abstract_session_store, monkeypatch):
    """
    unit tested:  create

    test case:
    creates a session_id by calling do_create and verifying it
    """
    masd = mock_abstract_session_store
    monkeypatch.setattr(masd, 'do_create', lambda x: 'sessionid123')
    result = masd.create(session='arbitrarysession')
    assert result == 'sessionid123'

def test_asd_verify_session_id_raises(mock_abstract_session_store):
    """
    unit tested:  verify_session_id

    test case:
    calling method with a None value raises and exception
    """
    masd = mock_abstract_session_store
    with pytest.raises(IllegalStateException):
        masd.verify_session_id(session_id=None)

def test_asd_verify_session_id_succeeds(mock_abstract_session_store):
    """
    unit tested:  verify_session_id

    test case:
    calling method with non-None value returns successfully
    """
    masd = mock_abstract_session_store
    masd.verify_session_id(session_id='arbitrarysessionid')


@pytest.mark.parametrize('session,sessionid', 
                         [('arbitrarysession', None), (None, 'sessionid123'),
                          (None, None)])
def test_asd_assign_session_id_raises(
        mock_abstract_session_store, session, sessionid):
    """
    unit tested:  assign_session_id

    test case:
     I) session = 'arbitrarysession' , session_id = None
    II) session = None, session_id = 'sessionid123'
   III) session = None, session_id = None    
    """
    masd = mock_abstract_session_store
    with pytest.raises(IllegalArgumentException):
        masd.assign_session_id(session, sessionid)    

def test_asd_assign_session_id_succeeds(mock_abstract_session_store):
    """
    unit tested:  assign_session_id

    test case:
    assigns the session_id attribute to a session
    """
    masd = mock_abstract_session_store
    mock_session = mock.MagicMock()
    masd.assign_session_id(mock_session, 'sessionid123') 
    assert mock_session.session_id == 'sessionid123'

def test_asd_read_session_raises(mock_abstract_session_store, monkeypatch):
    """
    unit tested:  read_session

    test case:
    read_session should raise an exception when it cannot find a session
    identified by the session_id parameter
    """
    masd = mock_abstract_session_store
    monkeypatch.setattr(masd, 'do_read_session', lambda x: None)
    with pytest.raises(UnknownSessionException):
        masd.read_session('sessionid123')    

def test_asd_read_session_succeeds(mock_abstract_session_store, monkeypatch):
    """
    unit tested:  read_session

    test case:
    read_session succeeds when do_read_session returns a session
    """
    masd = mock_abstract_session_store
    monkeypatch.setattr(masd, 'do_read_session', lambda x: 'mocksession')
    result = masd.read_session('sessionid123')
    assert result == 'mocksession'


# -----------------------------------------------------------------------------
# MemorySessionStore
# -----------------------------------------------------------------------------

def test_msd_do_create(memory_session_store):
    """
    unit tested:  do_create

    test case:
    generates a session id, assigns it to the session, and stores the session
    """
    msd = memory_session_store 

    with mock.patch.object(msd, 'generate_session_id') as mock_gsi:
        mock_gsi.return_value = 'sessionid123' 
        with mock.patch.object(msd, 'assign_session_id') as mock_asi:
            mock_asi.return_value = None
            with mock.patch.object(msd, 'store_session') as mock_ss:
                mock_ss.return_value = None

                ds = 'dumbsession'
                result = msd.do_create(ds)

                mock_gsi.assert_called_once_with(ds)
                mock_asi.assert_called_once_with(ds, 'sessionid123')
                mock_ss.assert_called_once_with('sessionid123', ds)
                assert result == 'sessionid123'

def test_msd_store_session(memory_session_store):
    """
    unit tested:  store_session

    test case:
    passing a valid (non-None) session_id and session will save it in the 
    sessions dict
    """
    msd = memory_session_store 
    result = msd.store_session(session_id='sessionid123', session='dumbsession')
    assert result == 'dumbsession'

@pytest.mark.parametrize("session_id, session",
                         [(None, 'dumbsession'), ('sessionid123', None)])
def test_msd_store_session_raises(memory_session_store, session_id, session):
    """
    unit tested:  store_session

    test case:
    if either session_id or session are not set, an exception will raise
    """
    msd = memory_session_store 
    with pytest.raises(IllegalArgumentException):
        msd.store_session(session_id, session)


@pytest.mark.parametrize("session_id, expected", 
                         [('sessionid123', 'sessionid123session'),
                          ('sessionid345', None)]) 
def test_msd_do_read_session(
        memory_session_store, monkeypatch, session_id, expected):
    """
    unit tested:  do_read_session

    test case:
    normal code path exercise, returning a value or None
    """
    msd = memory_session_store 
    monkeypatch.setitem(msd.sessions, 'sessionid123', 'sessionid123session')
    result = msd.do_read_session(session_id)
    assert result == expected


def test_msd_update(memory_session_store, mock_session):
    """
    unit tested:  update

    test case:
    calling update with a session will call store_session using it as param
    """
    msd = memory_session_store 
    result = msd.update(mock_session)
    assert result.session_id == mock_session.session_id

def test_msd_delete_raises_ae(memory_session_store):
    """
    unit tested:  delete

    test case:
    calling delete while passing a session without a session_id attribute will
    raise an AttributeError
    """
    msd = memory_session_store 
    with pytest.raises(IllegalArgumentException):
        msd.delete(session='dumbsession')

def test_msd_get_active_sessions(memory_session_store, monkeypatch, mock_session):
    """
    unit tested:  get_active_sessions

    test case:
    returns either an empty tuple or tuple containing the session objects
    """
    msd = memory_session_store 
    mysessions = {mock_session.session_id: mock_session}
    monkeypatch.setattr(msd, 'sessions', mysessions)
    result = msd.get_active_sessions()
    assert result == (mock_session,)

# -----------------------------------------------------------------------------
# CachingSessionStore
# -----------------------------------------------------------------------------

def test_csd_gasc_lazy_wo_activesessions(mock_caching_session_store, monkeypatch):
    """
    unit tested:  get_active_sessions_cache_lazy

    test case:
    no active_sessions attribute by default, so method gets called
    """
    mcsd = mock_caching_session_store
    monkeypatch.setattr(mcsd, 'create_active_sessions_cache', lambda: 'active')
    result = mcsd.get_active_sessions_cache_lazy()
    assert result == 'active'

def test_csd_gasc_lazy_w_activesessions(mock_caching_session_store, monkeypatch):
    """
    unit tested:  get_active_sessions_cache_lazy

    test case:
    when active_sessions attribute exists, it is returned
    """
    mcsd = mock_caching_session_store
    monkeypatch.setattr(mcsd, 'active_sessions', 'active')
    result = mcsd.get_active_sessions_cache_lazy()
    assert result == 'active'

def test_csd_create_active_sessions_cache_returns_value(
        mock_caching_session_store, monkeypatch):
    """
    unit tested:  create_active_sessions_cache
    
    test case:
    a cache manager returns a cache    
    """
    mcsd = mock_caching_session_store
    cm = type('CacheManager', (object,), {})()
    monkeypatch.setattr(cm, 'get_cache', lambda name: 'cacheX', raising=False)
    monkeypatch.setattr(mcsd, 'cache_manager', cm) 

    result = mcsd.create_active_sessions_cache()

    assert result == 'cacheX'


def test_csd_create_active_sessions_cache_returns_none(
        mock_caching_session_store, monkeypatch):
    """
    unit tested:  create_active_sessions_cache
    
    test case:
    a cache manager returns a cache else None    
    """
    mcsd = mock_caching_session_store
    result = mcsd.create_active_sessions_cache()
    assert result is None


def test_csd_create(mock_caching_session_store):
    """
    unit tested:  create

    test case:
    calls two methods and returns sessionid
    """
    mcsd = mock_caching_session_store
    with mock.patch.object(AbstractSessionStore, 'create') as mock_asdc:
        mock_asdc.return_value = 'sessionid123'
        with mock.patch.object(MockCachingSessionStore, 'cache') as mcsdc:
            mcsdc.return_value = None
            result = mcsd.create('session')
            mcsdc.assert_called_once_with(session='session', 
                                          session_id='sessionid123')
            assert result == 'sessionid123' 

def test_csd_getcachedsession_wo_cache(
        mock_caching_session_store, mock_cache, monkeypatch):
    """
    unit tested:  get_cached_session

    test case:
        when no cache param is passed, the cache is obtained by method call
        and then used to get the sessionid 
    """
    mcsd = mock_caching_session_store
    monkeypatch.setattr(mcsd, 'get_active_sessions_cache_lazy', lambda: mock_cache) 
    result = mcsd.get_cached_session('sessionid123')
    assert result == 'session_123'

def test_csd_getcachedsession_w_cache(
        mock_caching_session_store, mock_cache, monkeypatch):
    """
    unit tested:  get_cached_session

    test case:
        when cache param is passed, it is used to get the sessionid 
    """
    mcsd = mock_caching_session_store
    result = mcsd.get_cached_session(sessionid='sessionid123', cache=mock_cache)
    assert result == 'session_123'

def test_csd_getcachedsession_none_default(
        mock_caching_session_store, mock_cache, monkeypatch):
    """
    unit tested:  get_cached_session

    test case:
        when cache param is passed, it is used to get the sessionid 
    """
    mcsd = mock_caching_session_store
    dumb = type('DumbClass', (object,), {})()
    monkeypatch.setattr(mcsd, 'get_active_sessions_cache_lazy', lambda: dumb)
    result = mcsd.get_cached_session(sessionid='sessionid123')
    assert result is None

def test_csd_cache_with_cache_param(
        mock_caching_session_store, mock_cache, monkeypatch, mock_session):
    """
    unit tested:  cache 

    test case:
    uses cache param to put session away
    """
    mcsd = mock_caching_session_store
    with mock.patch.object(MockCache, 'put') as mockc_put:
        mcsd.cache(mock_session, 'sessionid123', mock_cache)
        mockc_put.assert_called_once_with('sessionid123', mock_session)

def test_csd_cache_without_cache_param(
        mock_caching_session_store, mock_cache, monkeypatch, mock_session):
    """
    unit tested:  cache 

    test case:
    gets active session cache and puts session away
    """
    mcsd = mock_caching_session_store
    with mock.patch.object(MockCachingSessionStore, 
                           'get_active_sessions_cache_lazy') as mock_csd:
        mock_csd.return_value = mock_cache
        with mock.patch.object(MockCache, 'put') as mockc_put:
            mcsd.cache(mock_session, 'sessionid123')
            mockc_put.assert_called_once_with('sessionid123', mock_session)
            mock_csd.assert_called_once_with()

def test_csd_read_session_exists(
        mock_caching_session_store, monkeypatch, mock_session):
    """
    unit tested:  read_session

    test case:
    get_cached_session returns a session, which in turn is returned by 
    read_session
    """
    mcsd = mock_caching_session_store
    monkeypatch.setattr(mcsd, 'get_cached_session', lambda x: mock_session)
    result = mcsd.read_session('sessionid123')
    assert result == mock_session

def test_csd_read_session_not_exists(
        mock_caching_session_store, monkeypatch, mock_session):
    """
    unit tested:  read_session

    test case:
    get_cached_session returns None, therefore super's read_session is called 
    """
    mcsd = mock_caching_session_store
    monkeypatch.setattr(mcsd, 'get_cached_session', lambda x: None) 
    with mock.patch.object(AbstractSessionStore, 'read_session') as abs_rs:
        abs_rs.return_value = mock_session 
        result = mcsd.read_session('sessionid123')
        assert result == mock_session

def test_csd_update_isvalid(mock_caching_session_store, mock_session):
    """
    unit tested:  update

    test case:
    when a validating session is passed, and the session is valid, cache is 
    called
    """
    mcsd = mock_caching_session_store
    with mock.patch.object(mcsd, 'do_update') as mock_doupdate:
        mock_doupdate.return_value = None
        with mock.patch.object(mcsd, 'cache') as mock_cache:
            mock_cache.return_value = None

            mcsd.update(mock_session)

            mock_doupdate.assert_called_once_with(mock_session)
            mock_cache.assert_called_once_with(
                session=mock_session, session_id=mock_session.session_id)

def test_csd_update_isnotvalid(
        mock_caching_session_store, mock_session, monkeypatch):
    """
    unit tested:  update

    test case:
    when a validating session is passed, and the session is invalid,
    uncache is called
    """
    mcsd = mock_caching_session_store
    monkeypatch.setattr(mock_session, '_isvalid', False)
    with mock.patch.object(mcsd, 'do_update') as mock_doupdate:
        mock_doupdate.return_value = None
        with mock.patch.object(mcsd, 'uncache') as mock_uncache:
            mock_uncache.return_value = None

            mcsd.update(mock_session)

            mock_doupdate.assert_called_once_with(mock_session)
            mock_uncache.assert_called_once_with(mock_session)


def test_csd_update_noisvalid(
        mock_caching_session_store, mock_session, monkeypatch):
    """
    unit tested:  update

    test case:
    when a session that is not of type ValidatingSession is passed, cache
    is called
    """
    mcsd = mock_caching_session_store
    monkeypatch.delattr(mock_session, '_isvalid')
    with mock.patch.object(mcsd, 'do_update') as mock_doupdate:
        mock_doupdate.return_value = None
        with mock.patch.object(mcsd, 'cache') as mock_cache:
            mock_cache.return_value = None

            mcsd.update(mock_session)

            mock_doupdate.assert_called_once_with(mock_session)
            mock_cache.assert_called_once_with(
                session=mock_session, session_id=mock_session.session_id)

def test_csd_delete(mock_caching_session_store):
    """
    unit tested:  delete

    test case:
    basic code path exercise
    """
    mcsd = mock_caching_session_store
    with mock.patch.object(mcsd, 'uncache') as mock_uncache:
        mock_uncache.return_value = None
        with mock.patch.object(mcsd, 'do_delete') as mock_dodelete:
            mock_dodelete.return_value = None
            mcsd.delete('session')
            mock_uncache.assert_called_once_with('session')
            mock_dodelete.assert_called_once_with('session')

def test_csd_uncache(
        mock_caching_session_store, mock_cache, mock_session, monkeypatch):
    """
    unit tested:  uncache

    test case:  
    cache is lazily obtained and session is removed by sessionid
    """
    mcsd = mock_caching_session_store
    monkeypatch.setattr(mcsd, 'get_active_sessions_cache_lazy', lambda: mock_cache) 
    with mock.patch.object(MockCache, 'remove') as mock_remove:
        mock_remove.return_value = None
        mcsd.uncache(mock_session)
        mock_remove.assert_called_once_with(mock_session.session_id)

def test_csd_uncache_raises(mock_caching_session_store):
    """
    unit tested:  uncache

    test case:
    cannot obtain cache, resulting in returned execution
    """
    mcsd = mock_caching_session_store
    mcsd.uncache('session') 

def test_csd_get_active_sessions_returns_cache(
        mock_caching_session_store, monkeypatch):
    """
    unit tested:  get_active_sessions

    test case:
    returns a tuple containing the one cache
    """
    mcsd = mock_caching_session_store
    mock_cache = MockCache({'cache': 'cache1'})
    with mock.patch.object(MockCachingSessionStore, 
                           'get_active_sessions_cache_lazy') as mock_gascl:
        mock_gascl.return_value = mock_cache
        results = mcsd.get_active_sessions()
        assert results == tuple(['cache1'])

def test_csd_get_active_sessions_returns_empty(mock_caching_session_store):
    """
    unit tested:  get_active_sessions

    test case:
    returns an empty tuple
    """
    mcsd = mock_caching_session_store
    results = mcsd.get_active_sessions()
    assert results == tuple() 
