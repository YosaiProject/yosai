from yosai import (
    settings,
)


class DefaultSubjectSettings:
    """
    DefaultSubjectSettings is a settings proxy.  It is new for Yosai.
    It obtains the subject configuration from Yosai's global settings
    and default values when no settings can be obtained.
    """
    def __init__(self):

        # omitted millisecond conversions

        subject_config = settings.SUBJECT_CONFIG
        self.default_context_names = subject_config.get('default_context')

    @property
    def default_context_attribute_names(self):
        return self.default_context_names 

    def __repr__(self):
        return ("SubjectSettings({0})".format(self.default_context))

# initalize module-level settings:
subject_settings = DefaultSubjectSettings()
