from yosai import (
    settings,
)


class SubjectSettings:
    """
    SubjectSettings is a settings proxy.  It is new for Yosai.
    It obtains the session configuration from Yosai's global settings
    and default values if there aren't any.
    """
    def __init__(self):
        subject_config = settings.SUBJECT_CONFIG

        subject_context = subject_config.get('subject_context')
        self.identifiers_session_key = subject_context.get('identifiers_session_key')
        self.authenticated_session_key = subject_context.get('authenticated_session_key')

    def __repr__(self):
        return "SubjectSettings(isk={0}, ask={1})".format(
            self.identifiers_session_key, self.authenticated_session_key)

# initalize module-level settings:
subject_settings = SubjectSettings()
