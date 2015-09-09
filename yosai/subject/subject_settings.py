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

        # default_context resolves aliases to their fully qualified key names
        self.context = subject_config.get('default_context')
        self.keys = self.context.values()

    def get_key(self, name):
        """
        returns the fully qualified key name from settings
        """
        return self.context.get(name)

    def __repr__(self):
        return ("SubjectSettings({0})".format(self.context))

# initalize module-level settings:
subject_settings = DefaultSubjectSettings()
