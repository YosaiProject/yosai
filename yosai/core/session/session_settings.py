import datetime


class SessionSettings:
    """
    SessionSettings is a settings proxy.  It is new for Yosai.
    It obtains the session configuration from Yosai's global settings
    and default values if there aren't any.
    """
    def __init__(self, settings):

        # omitted millisecond conversions

        session_config = settings.SESSION_CONFIG
        timeout_config = session_config.get('session_timeout', None)
        validation_config = session_config.get('session_validation', None)

        # convert to milliseconds:
        self.absolute_timeout = timeout_config.get('absolute_timeout', 1800)*1000  # def:30min
        self.idle_timeout = timeout_config.get('idle_timeout', 900)*1000  # def:15min

        self.validation_scheduler_enable =\
            validation_config.get('scheduler_enabled', True)

        self.interval = validation_config.get('time_interval', 3600)  # def:1hr
        self.validation_time_interval = datetime.timedelta(seconds=self.interval)

    def __repr__(self):
        return ("SessionSettings(absolute_timeout={0}, idle_timeout={1}, "
                "validation_scheduler_enable={2}, "
                "validation_time_interval={3})".
                format(
                    self.absolute_timeout,
                    self.idle_timeout,
                    self.validation_scheduler_enable,
                    self.validation_time_interval))
