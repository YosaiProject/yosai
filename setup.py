import os
import re

from setuptools import setup, find_packages, Command


class CleanCommand(Command):
    """Custom clean command to tidy up the project root."""
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        os.system('rm -vrf ./build ./dist ./*.pyc ./*.tgz ./*.egg-info')


here = os.path.abspath(os.path.dirname(__file__))

try:
    with open(os.path.join(here, 'yosai', 'core', '__init__.py')) as v:
        VERSION = re.compile(r".*__version__ = '(.*?)'", re.S).match(v.read()).group(1)
    with open(os.path.join(here, 'README.md')) as f:
        README = f.read()
except IOError:
    VERSION = README = ''

install_requires = [
    'PyYAML==3.11',
    'python-dateutil==2.4.2',
    'pytz==2016.1',
    'PyPubSub==3.3.0',
    'bcrypt==2.0.0',
    'passlib==1.6.5',
    'marshmallow==2.6.1',
    'cryptography==1.1.1',
    'msgpack-python==0.4.6',
    'python-rapidjson==0.0.6',
]

setup(
    name='yosai',
    version=VERSION,
    description="Yosai is a powerful security framework with an intuitive api.",
    long_description=README,
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Topic :: Security',
        'Topic :: Software Development :: Libraries :: Application Frameworks',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    keywords='security rbac session authentication authorization',
    author='Darin Gordon',
    author_email='dkcdkg@gmail.com',
    url='http://yosaiproject.github.io/yosai',
    license='Apache License 2.0',
    packages=find_packages('.', exclude=['ez_setup', 'test*']),
    install_requires=install_requires,
    zip_safe=False,
    cmdclass={'clean': CleanCommand}
)
