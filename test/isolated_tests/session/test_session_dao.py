import pytest
from unittest import mock
from yosai import (
    IllegalArgumentException,
    IllegalStateException,
    RandomSessionIDGenerator,
    UnknownSessionException,
    UUIDSessionIDGenerator,
)

# -----------------------------------------------------------------------------
# AbstractSessionDAO
# -----------------------------------------------------------------------------

@pytest.mark.parametrize('sessiongen', [UUIDSessionIDGenerator, 
                                        RandomSessionIDGenerator])
def test_asd_generate_session_id_succeeds(
        mock_abstract_session_dao, sessiongen, monkeypatch):
    """
    unit tested:  generate_session_id

    test case:
    successfully generates a session_id (str)
    """
    masd = mock_abstract_session_dao
    monkeypatch.setattr(masd, 'session_id_generator', sessiongen) 
    with mock.patch.object(sessiongen, 'generate_id') as mock_gen:
        mock_gen.return_value = 'sessionid1234'
        masd.generate_session_id(session='arbitrarysession')

def test_asd_generate_session_id_raises(mock_abstract_session_dao):
    """
    unit tested:  generate_session_id

    test case:
    when a session_id generator isn't assigned to the ASD, an exception raises
    """
    masd = mock_abstract_session_dao
    with mock.patch.object(RandomSessionIDGenerator, 'generate_id') as mock_gen:
        mock_gen.side_effect = AttributeError 
        with pytest.raises(IllegalStateException):
            masd.generate_session_id(session='arbitrarysession')

def test_asd_create_raises(mock_abstract_session_dao, monkeypatch):
    """
    unit tested:  create

    test case:
    create calls verify_session_id, which will raise when session_id is None
    """
    masd = mock_abstract_session_dao
    monkeypatch.setattr(masd, 'do_create', lambda x: None)
    with pytest.raises(IllegalStateException):
        masd.create(session='arbitrarysession')

def test_asd_create_succeeds(mock_abstract_session_dao, monkeypatch):
    """
    unit tested:  create

    test case:
    creates a session_id by calling do_create and verifying it
    """
    masd = mock_abstract_session_dao
    monkeypatch.setattr(masd, 'do_create', lambda x: 'sessionid123')
    result = masd.create(session='arbitrarysession')
    assert result == 'sessionid123'

def test_asd_verify_session_id_raises(mock_abstract_session_dao):
    """
    unit tested:  verify_session_id

    test case:
    calling method with a None value raises and exception
    """
    masd = mock_abstract_session_dao
    with pytest.raises(IllegalStateException):
        masd.verify_session_id(session_id=None)

def test_asd_verify_session_id_succeeds(mock_abstract_session_dao):
    """
    unit tested:  verify_session_id

    test case:
    calling method with non-None value returns successfully
    """
    masd = mock_abstract_session_dao
    masd.verify_session_id(session_id='arbitrarysessionid')


@pytest.mark.parametrize('session,sessionid', 
                         [('arbitrarysession', None), (None, 'sessionid123'),
                          (None, None)])
def test_asd_assign_session_id_raises(
        mock_abstract_session_dao, session, sessionid):
    """
    unit tested:  assign_session_id

    test case:
     I) session = 'arbitrarysession' , session_id = None
    II) session = None, session_id = 'sessionid123'
   III) session = None, session_id = None    
    """
    masd = mock_abstract_session_dao
    with pytest.raises(IllegalArgumentException):
        masd.assign_session_id(session, sessionid)    

def test_asd_assign_session_id_succeeds(mock_abstract_session_dao):
    """
    unit tested:  assign_session_id

    test case:
    assigns the session_id attribute to a session
    """
    masd = mock_abstract_session_dao
    mock_session = mock.MagicMock()
    masd.assign_session_id(mock_session, 'sessionid123') 
    assert mock_session.session_id == 'sessionid123'

def test_asd_read_session_raises(mock_abstract_session_dao, monkeypatch):
    """
    unit tested:  read_session

    test case:
    read_session should raise an exception when it cannot find a session
    identified by the session_id parameter
    """
    masd = mock_abstract_session_dao
    monkeypatch.setattr(masd, 'do_read_session', lambda x: None)
    with pytest.raises(UnknownSessionException):
        masd.read_session('sessionid123')    

def test_asd_read_session_succeeds(mock_abstract_session_dao, monkeypatch):
    """
    unit tested:  read_session

    test case:
    read_session succeeds when do_read_session returns a session
    """
    masd = mock_abstract_session_dao
    monkeypatch.setattr(masd, 'do_read_session', lambda x: 'mocksession')
    result = masd.read_session('sessionid123')
    assert result == 'mocksession'


# -----------------------------------------------------------------------------
# MemorySessionDAO
# -----------------------------------------------------------------------------

def test_msd_do_create(memory_session_dao):
    """
    unit tested:  do_create

    test case:
    generates a session id, assigns it to the session, and stores the session
    """
    msd = memory_session_dao 

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

def test_msd_store_session(memory_session_dao):
    """
    unit tested:  store_session

    test case:
    passing a valid (non-None) session_id and session will save it in the 
    sessions dict
    """
    msd = memory_session_dao 
    result = msd.store_session(session_id='sessionid123', session='dumbsession')
    assert result == 'dumbsession'

@pytest.mark.parametrize("session_id, session",
                         [(None, 'dumbsession'), ('sessionid123', None)])
def test_msd_store_session_raises(memory_session_dao, session_id, session):
    """
    unit tested:  store_session

    test case:
    if either session_id or session are not set, an exception will raise
    """
    msd = memory_session_dao 
    with pytest.raises(IllegalArgumentException):
        msd.store_session(session_id, session)


@pytest.mark.parametrize("session_id, expected", 
                         [('sessionid123', 'sessionid123session'),
                          ('sessionid345', None)]) 
def test_msd_do_read_session(
        memory_session_dao, monkeypatch, session_id, expected):
    """
    unit tested:  do_read_session

    test case:
    normal code path exercise, returning a value or None
    """
    msd = memory_session_dao 
    monkeypatch.setitem(msd.sessions, 'sessionid123', 'sessionid123session')
    result = msd.do_read_session(session_id)
    assert result == expected


def test_msd_update(memory_session_dao, mock_session):
    """
    unit tested:  update

    test case:
    calling update with a session will call store_session using it as param
    """
    msd = memory_session_dao 
    result = msd.update(mock_session)
    assert result.session_id == mock_session.session_id

def test_msd_delete_raises_ae(memory_session_dao):
    """
    unit tested:  delete

    test case:
    calling delete while passing a session without a session_id attribute will
    raise an AttributeError
    """
    msd = memory_session_dao 
    with pytest.raises(IllegalArgumentException):
        msd.delete(session='dumbsession')

def test_msd_get_active_sessions(memory_session_dao, monkeypatch, mock_session):
    """
    unit tested:  get_active_sessions

    test case:
    returns either an empty tuple or tuple containing the session objects
    """
    msd = memory_session_dao 
    mysessions = {mock_session.session_id: mock_session}
    monkeypatch.setattr(msd, 'sessions', mysessions)
    result = msd.get_active_sessions()
    assert result == (mock_session,)

# -----------------------------------------------------------------------------
# CachingSessionDAO
# -----------------------------------------------------------------------------

