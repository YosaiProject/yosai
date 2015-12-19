import pytest
from unittest import mock
from yosai.core import (
    AbstractSessionStore,
    CachingSessionStore,
    DefaultSessionKey,
    IllegalArgumentException,
    IllegalStateException,
    RandomSessionIDGenerator,
    SessionCacheException,
    UnknownSessionException,
    UUIDSessionIDGenerator,
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
    monkeypatch.setattr(masd, '_do_create', lambda x: 'sessionid123')
    with mock.patch.object(AbstractSessionStore, 'verify_session_id') as vsi:
        vsi.return_value = None
        result = masd.create(session='arbitrarysession')
        vsi.assert_called_once_with('sessionid123')
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


def test_asd_read_raises(mock_abstract_session_store, monkeypatch):
    """
    unit tested:  read

    test case:
    read should raise an exception when it cannot find a session
    identified by the session_id parameter
    """
    masd = mock_abstract_session_store
    monkeypatch.setattr(masd, '_do_read', lambda x: None)
    with pytest.raises(UnknownSessionException):
        masd.read('sessionid123')


def test_asd_read_succeeds(mock_abstract_session_store, monkeypatch):
    """
    unit tested:  read

    test case:
    read_session succeeds when do_read returns a session
    """
    masd = mock_abstract_session_store
    monkeypatch.setattr(masd, '_do_read', lambda x: 'mocksession')
    result = masd.read('sessionid123')
    assert result == 'mocksession'


# -----------------------------------------------------------------------------
# MemorySessionStore
# -----------------------------------------------------------------------------

def test_msd_do_create(memory_session_store):
    """
    unit tested:  _do_create

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
                result = msd._do_create(ds)

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
    unit tested:  do_read

    test case:
    normal code path exercise, returning a value or None
    """
    msd = memory_session_store
    monkeypatch.setitem(msd.sessions, 'sessionid123', 'sessionid123session')
    result = msd._do_read(session_id)
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


# -----------------------------------------------------------------------------
# CachingSessionStore
# -----------------------------------------------------------------------------

def test_csd_create(caching_session_store):
    """
    unit tested:  create

    test case:
    calls two methods and returns sessionid
    """
    csd = caching_session_store
    with mock.patch.object(AbstractSessionStore, 'create') as mock_asdc:
        mock_asdc.return_value = 'sessionid123'
        with mock.patch.object(CachingSessionStore, '_cache') as csdc:
            csdc.return_value = None
            with mock.patch.object(CachingSessionStore,
                                   '_cache_identifiers_to_key_map') as cikm:
                cikm.return_value = None
                result = csd.create('session')
                csdc.assert_called_once_with('session', 'sessionid123')
                cikm.assert_called_once_with('session', 'sessionid123')
                assert result == 'sessionid123'


def test_csd_read_session_exists(
        caching_session_store, monkeypatch, mock_session):
    """
    unit tested:  read

    test case:
    _get_cached_session returns a session, which in turn is returned by
    read
    """
    csd = caching_session_store
    monkeypatch.setattr(csd, '_get_cached_session', lambda x: mock_session)
    result = csd.read('sessionid123')
    assert result == mock_session


def test_csd_update_isvalid(caching_session_store, mock_session):
    """
    unit tested:  update

    test case:
    when a valid session is passed, cache is called
    """
    csd = caching_session_store

    with mock.patch.object(csd, '_cache') as mock_cache_handler:
        mock_cache_handler.return_value = None

        with mock.patch.object(csd, '_cache_identifiers_to_key_map') as cikm:
            cikm.return_value = None

            csd.update(mock_session)

            mock_cache_handler.assert_called_once_with(
                mock_session, mock_session.session_id)

            cikm.assert_called_once_with(
                mock_session, mock_session.session_id)


def test_csd_update_isnotvalid(
        caching_session_store, mock_session, monkeypatch):
    """
    unit tested:  update

    test case:
    when a validating session is passed, and the session is invalid,
    uncache is called
    """
    csd = caching_session_store
    monkeypatch.setattr(mock_session, '_isvalid', False)
    with mock.patch.object(csd, '_uncache') as mock_uncache:
        mock_uncache.return_value = None

        csd.update(mock_session)

        mock_uncache.assert_called_once_with(mock_session)


def test_csd_delete(caching_session_store):
    """
    unit tested:  delete

    test case:
    basic code path exercise
    """
    csd = caching_session_store
    with mock.patch.object(csd, '_uncache') as mock_uncache:
        mock_uncache.return_value = None
        csd.delete('session')
        mock_uncache.assert_called_once_with('session')


def test_csd_getcachedsession_returns(
        caching_session_store, mock_cache_handler, monkeypatch):
    """
    unit tested:  _get_cached_session

    test case:
        when no cache param is passed, the cache is obtained by method call
        and then used to get the sessionid
    """
    csd = caching_session_store
    monkeypatch.setattr(mock_cache_handler, 'get',
                        lambda domain, identifier: 'session_123')
    monkeypatch.setattr(csd, 'cache_handler', mock_cache_handler)
    result = csd._get_cached_session('sessionid123')
    assert result == 'session_123'


def test_csd_getcachedsession_none_default(
        caching_session_store, mock_cache_handler, monkeypatch):
    """
    unit tested:  get_cached_session

    test case:
        when cache param is passed, it is used to get the sessionid
    """
    csd = caching_session_store
    result = csd._get_cached_session(sessionid='sessionid123')
    assert result is None


def test_csd_cache_identifiers_to_key_map_w_idents(
        caching_session_store, mock_cache_handler, mock_session, monkeypatch,
        simple_identifier_collection):
    sic = simple_identifier_collection
    csd = caching_session_store
    monkeypatch.setattr(csd, 'cache_handler', mock_cache_handler)
    monkeypatch.setattr(mock_session, 'get_internal_attribute', lambda x: sic)

    with mock.patch.object(mock_cache_handler, 'set') as mock_set:
        mock_set.return_value = None

        csd._cache_identifiers_to_key_map(mock_session, 'sessionid123')

        mock_set.assert_called_once_with(domain='session',
                                         identifier=sic.primary_identifier,
                                         value=DefaultSessionKey('sessionid123'))


def test_csd_cache_identifiers_to_key_map_wo_idents(
        caching_session_store, mock_cache_handler, mock_session, monkeypatch,
        capsys):

    csd = caching_session_store
    monkeypatch.setattr(csd, 'cache_handler', mock_cache_handler)
    with mock.patch.object(mock_cache_handler, 'set') as mock_set:
        mock_set.return_value = None

        csd._cache_identifiers_to_key_map(mock_session, 'sessionid123')


def test_csd_cache_with_cachehandler(
        caching_session_store, mock_cache_handler, monkeypatch, mock_session):
    """
    unit tested:  cache

    test case:
    uses cache_handler to set session entry
    """
    csd = caching_session_store
    monkeypatch.setattr(csd, 'cache_handler', mock_cache_handler)

    with mock.patch.object(mock_cache_handler, 'set') as ch_set:
        ch_set.return_value = None
        csd._cache(mock_session, 'sessionid123')
        ch_set.assert_called_once_with(domain='session',
                                       identifier='sessionid123',
                                       value=mock_session)


def test_csd_cache_without_cache_handler(
        caching_session_store, mock_cache_handler, monkeypatch, mock_session):
    """
    unit tested:  cache

    test case:
    gets active session cache and puts session away
    """
    csd = caching_session_store
    with pytest.raises(SessionCacheException):
        csd._cache(mock_session, 'sessionid123')


def test_csd_uncache(
        caching_session_store, mock_cache_handler, mock_session, monkeypatch,
        simple_identifier_collection):
    """
    unit tested:  uncache

    test case:
    session is removed by sessionid
    """
    csd = caching_session_store
    sic = simple_identifier_collection
    monkeypatch.setattr(csd, 'cache_handler', mock_cache_handler)
    monkeypatch.setattr(mock_session, 'get_internal_attribute', lambda x: sic)
    with mock.patch.object(mock_cache_handler, 'delete') as mock_remove:
        mock_remove.return_value = None
        csd._uncache(mock_session)
        calls = [mock.call(domain='session', identifier=mock_session.session_id),
                 mock.call(domain='session', identifier=sic.primary_identifier)]
        mock_remove.assert_has_calls(calls)


def test_csd_uncache_raises(caching_session_store):
    """
    unit tested:  uncache

    test case:
    cannot obtain cache, resulting in returned execution
    """
    csd = caching_session_store

    with pytest.raises(SessionCacheException):
        csd._uncache('session')
