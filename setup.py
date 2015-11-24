import os
import re
import sys

from setuptools import setup, find_packages, Command
from setuptools.command.test import test as TestCommand


class CleanCommand(Command):
    """Custom clean command to tidy up the project root."""
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        os.system('rm -vrf ./build ./dist ./*.pyc ./*.tgz ./*.egg-info')


class PyTest(TestCommand):
    user_options = [('pytest-args=', 'a', "Arguments to pass to py.test")]

    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.pytest_args = []

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        # import here, cause outside the eggs aren't loaded
        import pytest
        errno = pytest.main(self.pytest_args)
        sys.exit(errno)


v = open(os.path.join(os.path.dirname(__file__), 'yosai', '__init__.py'))
VERSION = re.compile(r".*__version__ = '(.*?)'", re.S).match(v.read()).group(1)
v.close()

readme = os.path.join(os.path.dirname(__file__), 'README.md')

setup(
    name='yosai',
    version=VERSION,
    description="A security framework featuring session management, authentication, and authorization",
    long_description=open(readme).read(),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
    ],
    keywords='security,rbac,session,authentication,authorization',
    author='Darin Gordon',
    author_email='dkcdkg@gmail.com',
    url='https://github.com/YosaiProject/yosai',
    license='Apache License 2.0',
    packages=find_packages('.', exclude=['ez_setup', 'test*']),
    zip_safe=False,
    tests_require=['pytest', 'pytest-cov', 'mock'],
    cmdclass={'test': PyTest,
              'clean': CleanCommand}
)
