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


# -----------------------------------------------------------------------------
# CachingSessionDAO
# -----------------------------------------------------------------------------

