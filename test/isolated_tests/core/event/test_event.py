from unittest import mock

# -----------------------------------------------------------------------------
# EventLogger Tests
# -----------------------------------------------------------------------------


@mock.patch('yosai.core.event.event.logger')
def test_eventlogger_log_authc_event(mock_logger, event_logger, caplog):
    mock_topic = mock.MagicMock()
    mock_topic.getName.return_value = 'SOMETHING'
    event_logger.log_authc_event(identifier='identifier', topic=mock_topic)
    mock_logger.info.assert_called_once_with(mock_topic.getName(),
                                             extra={'identifier': 'identifier'})


@mock.patch('yosai.core.event.event.logger')
def test_eventlogger_log_session_event(mock_logger, event_logger, caplog):
    mock_topic = mock.MagicMock()
    mock_topic.getName.return_value = 'SOMETHING'
    mock_items = mock.MagicMock(session_id='session_id')
    event_logger.log_session_event(items=mock_items, topic=mock_topic)
    mock_logger.info.assert_called_once_with(mock_topic.getName(),
                                             extra={'identifier': mock_items.identifiers.primary_identifier,
                                                    'session_id': mock_items.session_id})


@mock.patch('yosai.core.event.event.logger')
def test_eventlogger_log_authz_event(
        mock_logger, event_logger, simple_identifiers_collection):
    sic = simple_identifiers_collection
    mock_topic = mock.MagicMock()
    mock_topic.getName.return_value = 'SOMETHING'
    mock_items = mock.MagicMock(session_id='session_id')
    event_logger.log_authz_event(identifiers=sic,
                                 items=mock_items,
                                 topic=mock_topic)
    mock_logger.info.assert_called_once_with(mock_topic.getName(),
                                             extra={'identifiers': sic.__getstate__(),
                                                    'items': mock_items,
                                                    'logical_operator': None.__class__.__name__})
