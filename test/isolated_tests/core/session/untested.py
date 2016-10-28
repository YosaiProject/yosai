import pytest
from unittest import mock

# ----------------------------------------------------------------------------
# ExecutorServiceSessionValidationScheduler
# ----------------------------------------------------------------------------


def test_esvs_enable_session_validation(executor_session_validation_scheduler):
    """
    unit tested:  enable_session_validation

    test case:
    interval is set, so service.start() will be invoked and enabled = True
    """

    esvs = executor_session_validation_scheduler
    sse = StoppableScheduledExecutor  # from yosai.concurrency
    with mock.patch.object(sse, 'start') as sse_start:
        esvs.enable_session_validation()
        sse_start.assert_called_with() and esvs.is_enabled


def test_esvs_run(executor_session_validation_scheduler):
    """
    unit tested:  run

    test case:
    session_manager.validate_sessions is invoked
    """
    esvs = executor_session_validation_scheduler

    with mock.patch.object(MockAbstractNativeSessionManager,
                           'validate_sessions') as sm_vs:
        sm_vs.return_value = None
        esvs.run()
        sm_vs.assert_called_with()

def test_esvs_disable_session_validation(executor_session_validation_scheduler):
    """
    unit tested:  disable_session_validation

    test case:
    interval is set, so service.stop() will be invoked and enabled = False
    """

    esvs = executor_session_validation_scheduler
    sse = StoppableScheduledExecutor  # from yosai.concurrency
    with mock.patch.object(sse, 'stop') as sse_stop:
        esvs.disable_session_validation()
        sse_stop.assert_called_with() and not esvs.is_enabled

# ----------------------------------------------------------------------------
# AbstractValidatingSessionManager
# ----------------------------------------------------------------------------

@pytest.mark.parametrize(
    'svse,scheduler,scheduler_enabled,expected_result',
    [(True, True, False, True),
     (True, True, True, False),
     (False, True, False, False),
     (True, False, None, True)])
def test_avsm_esvin(abstract_validating_session_manager, monkeypatch,
                    svse, scheduler, scheduler_enabled, expected_result,
                    executor_session_validation_scheduler):
    """
    unit tested:  enable_session_validation_if_necessary

    test case:
    sets a scheduler, defaulting to that from init else enable_session_validation

    I) session_validation_scheduler_enabled = True
       scheduler = self.session_validation_scheduler
       scheduler.enabled = False
   II) session_validation_scheduler_enabled = True
       scheduler = self.session_validation_scheduler
       scheduler.enabled = True
  III) session_validation_scheduler_enabled = False
       scheduler = self.session_validation_scheduler
   IV) session_validation_scheduler_enabled = True
       scheduler = None
    """
    myscheduler = None
    if scheduler:
        myscheduler = executor_session_validation_scheduler
        monkeypatch.setattr(myscheduler, '_enabled', scheduler_enabled)

    avsm = abstract_validating_session_manager
    monkeypatch.setattr(avsm, 'session_validation_scheduler', myscheduler)
    monkeypatch.setattr(avsm, 'session_validation_scheduler_enabled', svse)

    with mock.patch.object(AbstractValidatingSessionManager,
                           'enable_session_validation') as avsm_esv:
        avsm_esv.return_value = None
        avsm.enable_session_validation_if_necessary()
        assert avsm_esv.called == expected_result



def test_avsm_do_validate(abstract_validating_session_manager, mock_session):
    """
    unit tested:  do_validate

    test case:
    basic code path exercise where method is called and successfully finishes
    """
    avsm = abstract_validating_session_manager
    assert avsm.do_validate(mock_session) is None


def test_avsm_do_validate_raises(abstract_validating_session_manager):
    """
    unit tested:  do_validate

    test case:
    session.validate is missing, raising an AttributeError which in turn raises
    IllegalStateException
    """
    avsm = abstract_validating_session_manager

    mock_session = type('DumbSession', (object,), {})()

    with pytest.raises(IllegalStateException):
        avsm.do_validate(mock_session)

def test_avsm_create_svs(abstract_validating_session_manager):
    """
    unit tested: create_session_validation_scheduler

    test case:
    basic codepath exercise that returns a scheduler instance
    """
    avsm = abstract_validating_session_manager
    result = avsm.create_session_validation_scheduler()
    assert isinstance(result, ExecutorServiceSessionValidationScheduler)


def test_avsm_esv_schedulerexists(
    abstract_validating_session_manager,
        executor_session_validation_scheduler, monkeypatch):
    """
    unit tested: enable_session_validation

    test case:
    a scheduler is already set, so no new one is created, and two methods
    called
    """
    avsm = abstract_validating_session_manager
    esvs = executor_session_validation_scheduler

    monkeypatch.setattr(avsm, 'session_validation_scheduler', esvs)

    with mock.patch.object(ExecutorServiceSessionValidationScheduler,
                           'enable_session_validation') as scheduler_esv:
        scheduler_esv.return_value = None
        with mock.patch.object(MockAbstractValidatingSessionManager,
                               'after_session_validation_enabled') as asve:
            asve.return_value = None

            avsm.enable_session_validation()

            scheduler_esv.assert_called_with()
            asve.assert_called_with()

def test_avsm_esv_schedulernotexists(
        abstract_validating_session_manager, monkeypatch,
        default_native_session_manager):
    """
    unit tested:  enable_session_validation

    test case:
    no scheduler is set, so a new one is created and set, and then two
    methods called
    """
    avsm = abstract_validating_session_manager
    mock_csvs = mock.MagicMock()
    mock_asve = mock.MagicMock()
    monkeypatch.setattr(avsm, 'create_session_validation_scheduler', mock_csvs)
    monkeypatch.setattr(avsm, 'after_session_validation_enabled', mock_asve)

    avsm.enable_session_validation()
    scheduler_esv = avsm.session_validation_scheduler.enable_session_validation
    assert (scheduler_esv.called and mock_asve.called)


def test_avsm_disable_session_validation_withscheduler_succeeds(
        abstract_validating_session_manager, monkeypatch):
    """
    unit tested:  disable_session_validation

    test case:
    with a scheduler set, the scheduler's disable_session_validation is called
    and succeeds, and then session_validation_scheduler is set to None
    """
    avsm = abstract_validating_session_manager
    scheduler = ExecutorServiceSessionValidationScheduler

    with mock.patch.object(MockAbstractValidatingSessionManager,
                           'before_session_validation_disabled') as mock_bsvd:
        mock_bsvd.return_value = None

        with mock.patch.object(scheduler, 'disable_session_validation') as dsv:
            dsv.return_value = None

            sched = scheduler(session_manager=avsm, interval=60)
            monkeypatch.setattr(avsm, 'session_validation_scheduler', sched)

            avsm.disable_session_validation()

            assert (mock_bsvd.called and dsv.called and
                    avsm.session_validation_scheduler is None)

def test_avsm_disable_session_validation_withscheduler_fails(
        abstract_validating_session_manager, monkeypatch):
    """
    unit tested:  disable_session_validation

    test case:
    with a scheduler set, the scheduler's disable_session_validation is called
    and fails, and then session_validation_scheduler is set to None
    """
    avsm = abstract_validating_session_manager

    scheduler = ExecutorServiceSessionValidationScheduler

    with mock.patch.object(MockAbstractValidatingSessionManager,
                           'before_session_validation_disabled') as mock_bsvd:
        mock_bsvd.return_value = None

        with mock.patch.object(scheduler, 'disable_session_validation') as dsv:
            dsv.side_effect = AttributeError

            sched = scheduler(session_manager=avsm, interval=60)
            monkeypatch.setattr(avsm, 'session_validation_scheduler', sched)

            avsm.disable_session_validation()

            assert (mock_bsvd.called and dsv.called and
                    avsm.session_validation_scheduler is None)


def test_avsm_disable_session_validation_without_scheduler(
        abstract_validating_session_manager, monkeypatch):
    """
    unit tested:  disable_session_validation

    test case:
    without a scheduler set,  only before_session_validation_disabled is called
    """
    avsm = abstract_validating_session_manager

    with mock.patch.object(MockAbstractValidatingSessionManager,
                           'before_session_validation_disabled') as mock_bsvd:
        mock_bsvd.return_value = None

        avsm.disable_session_validation()

        assert mock_bsvd.called and avsm.session_validation_scheduler is None


def test_avsm_validate_sessions_raises(
        abstract_validating_session_manager, monkeypatch):
    """
    unit tested:  validate_sessions

    test case:
    get_active_sessions() is called, returning a list containing THREE sessions
        - the first session succeeds to validate
        - the second session raises ExpiredSessionException from validate
        - the third session raises StoppedSessionException from validate
    """
    avsm = abstract_validating_session_manager

    valid_session = mock.MagicMock()
    expired_session = mock.MagicMock()
    stopped_session = mock.MagicMock()
    expired_session.validate.side_effect = ExpiredSessionException
    stopped_session.validate.side_effect = StoppedSessionException
    active_sessions = [valid_session, expired_session, stopped_session]

    monkeypatch.setattr(avsm, 'get_active_sessions', lambda: active_sessions)

    with mock.patch('yosai.SessionKey') as dsk:
        dsk.return_value = 'sessionkey123'
        results = avsm.validate_sessions()
        assert '[2] sessions' in results

def test_avsm_validate_sessions_allvalid(
        abstract_validating_session_manager, monkeypatch):
    """
    unit tested:  validate_sessions

    test case:
    get_active_sessions() is called, returning a list containing TWO sessions
        - the first session succeeds to validate
        - the second session succeeds to validate
    """
    avsm = abstract_validating_session_manager

    valid_session1 = mock.MagicMock()
    valid_session2 = mock.MagicMock()

    active_sessions = [valid_session1, valid_session2]

    monkeypatch.setattr(avsm, 'get_active_sessions', lambda: active_sessions)

    with mock.patch('yosai.SessionKey') as dsk:
        dsk.return_value = 'sessionkey123'
        results = avsm.validate_sessions()
        assert 'No sessions' in results
