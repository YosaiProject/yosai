"""
Following are the settings and configuration for Yosai.

Yosai follows a custom-else-default method of obtaining configuration 
settings: First, it obtains customized, user-specied configuration.  Any
other required configuration attributes that are unavailable through customized
configuration are obtained by (global) default settings.

This design is inspired by, or a copy of, source code written for Django.
"""

import os
from yosai import FileNotFoundException, MisconfiguredException
import anyjson as json

ENV_VAR = "YOSAI_SETTINGS_MODULE"
empty = object()


class LazySettings(object):
    """
    LazyConfig proxies the custom-else-default settings configuration process.
    Required settings that are not user-defined (custom) will default to those
    specified in default settings.
    """
    _wrapped = None

    def __init__(self):
        self._wrapped = empty

    def __getattr__(self, name):
        if self._wrapped is empty:
            self._setup(name)
        return getattr(self._wrapped, name)

    def __setattr__(self, name, value):
        if name == "_wrapped":
            # Assign to __dict__ to avoid infinite __setattr__ loops.
            self.__dict__["_wrapped"] = value
        else:
            if self._wrapped is empty:
                self._setup()
            setattr(self._wrapped, name, value)

    def __delattr__(self, name):
        if name == "_wrapped":
            raise TypeError("can't delete _wrapped.")
        if self._wrapped is empty:
            self._setup()
        delattr(self._wrapped, name)

    @property
    def configured(self):
        return self._wrapped is not empty

    def _setup(self, name=None):
        """
        Load the settings module referenced by ENV_VAR. This environment-
        defined configuration process is called during the settings
        configuration process.
        """
        settings_file = os.environ.get(ENV_VAR)
        if not settings_file:
            msg = ("Requested {desc}, but settings are not configured. "
                   "You must define the environment variable {env}. ".
                   format(desc=("setting: " + name) if name else "settings",
                          env=ENV_VAR))

            raise MisconfiguredException(msg)

        self._wrapped = Settings(settings_file)


class Settings(object):

    def __init__(self, settings_filepath='yosai_settings.json'):
        self.load_config(settings_filepath)

    def load_config(self, filepath):
        if os.path.exists(filepath):
            with open(filepath) as conf_file:
                config = json.loads(conf_file.read())
        else:
            raise FileNotFoundException('could not locate: ' + str(filepath)) 

        try:
            tempdict = {}
            tempdict.update(self.__dict__)
            tempdict.update(config)
            self.__dict__ = tempdict
        except (AttributeError, TypeError):
            raise MisconfiguredException('Settings failed to load attrs')


settings = LazySettings()
