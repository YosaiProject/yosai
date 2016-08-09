"""
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
"""
from importlib import import_module
import inspect
import sys
import collections
import datetime
import time
import threading


class ThreadStateManager(threading.local):
    def __init__(self):
        self.stack = []


class memoized_property:
    """A read-only @property that is only evaluated once.  Copied from
       dogpile.cache (created by Mike Bayer et al)."""
    def __init__(self, fget, doc=None):
        self.counter = 10
        self.fget = fget
        self.__doc__ = doc or fget.__doc__
        self.__name__ = fget.__name__

    def __get__(self, obj, cls):
        if obj is None:
            return self
        result = self.fget(obj)
        setattr(obj, self.__name__, result)

        self.counter += 1
        return result


def unix_epoch_time():
    return int(time.mktime(datetime.datetime.now().timetuple()))


class OrderedSet(collections.MutableSet):
    # The Following recipe was posted by Raymond Hettinger
    # at:  http://code.activestate.com/recipes/576694/

    def __init__(self, iterable=None):
        self.end = end = []
        end += [None, end, end]         # sentinel node for doubly linked list
        self.map = {}                   # key --> [key, prev, next]
        if iterable is not None:
            self |= iterable

    def __len__(self):
        return len(self.map)

    def __contains__(self, key):
        return key in self.map

    def add(self, key):
        if key not in self.map:
            end = self.end
            curr = end[1]
            curr[2] = end[1] = self.map[key] = [key, curr, end]

    def discard(self, key):
        if key in self.map:
            key, prev, next = self.map.pop(key)
            prev[2] = next
            next[1] = prev

    def __iter__(self):
        end = self.end
        curr = end[2]
        while curr is not end:
            yield curr[0]
            curr = curr[2]

    def __reversed__(self):
        end = self.end
        curr = end[1]
        while curr is not end:
            yield curr[0]
            curr = curr[1]

    def pop(self, last=True):
        if not self:
            raise KeyError('set is empty')
        key = self.end[1][0] if last else self.end[2][0]
        self.discard(key)
        return key

    def __repr__(self):
        if not self:
            return '%s()' % (self.__class__.__name__,)
        return '%s(%r)' % (self.__class__.__name__, list(self))

    def __eq__(self, other):
        if isinstance(other, OrderedSet):
            return len(self) == len(other) and list(self) == list(other)
        return set(self) == set(other)


def caller_module(depth=1):
    frm = inspect.stack()[depth + 1]
    caller = inspect.getmodule(frm[0])
    return caller


def caller_package(depth=1):
    module = caller_module(depth + 1)
    f = getattr(module, '__file__', '')
    if '__init__.py' in f:
        # module is a package
        return module

    # go up one level to get the package
    package_name = module.__name__.rsplit('.', 1)[0]
    return sys.modules[package_name]


# borrowed from pyramid.path.DottedNameResolver
def maybe_resolve(value, package=None):
    if not isinstance(value, str):
        return value

    if package is None and value.startswith('.'):
        package = caller_package()

    module = getattr(package, '__name__', None)  # package may be None
    if not module:
        module = None
    if value == '.':
        if module is None:
            raise ValueError(
                'relative name %r irresolveable without package' % (value,)
            )
        name = module.split('.')
    else:
        name = value.split('.')
        if not name[0]:
            if module is None:
                raise ValueError(
                    'relative name %r irresolveable without '
                    'package' % (value,))
            module = module.split('.')
            name.pop(0)
            while not name[0]:
                module.pop()
                name.pop(0)
            name = module + name

    used = name.pop(0)
    found = __import__(used)
    for n in name:
        used += '.' + n
        try:
            found = getattr(found, n)
        except AttributeError:
            __import__(used)
            found = getattr(found, n)  # pragma: no cover

    return found


# from asphalt:
def resolve_reference(ref):
    """
    Return the object pointed to by ``ref``.
    If ``ref`` is not a string or does not contain ``:``, it is returned as is.
    References must be in the form  <modulename>:<varname> where <modulename> is the fully
    qualified module name and varname is the path to the variable inside that module.
    For example, "concurrent.futures:Future" would give you the
    :class:`~concurrent.futures.Future` class.
    :raises LookupError: if the reference could not be resolved
    """
    if not isinstance(ref, str) or ':' not in ref:
        return ref

    modulename, rest = ref.split(':', 1)
    try:
        obj = import_module(modulename)
    except ImportError as e:
        raise LookupError(
            'error resolving reference {}: could not import module'.format(ref)) from e

    try:
        for name in rest.split('.'):
            obj = getattr(obj, name)
        return obj
    except AttributeError:
        raise LookupError('error resolving reference {}: error looking up object'.format(ref))


def qualified_name(obj):
    """Return the qualified name (e.g. package.module.Type) for the given object."""
    try:
        module = obj.__module__
        qualname = obj.__qualname__
    except AttributeError:
        type_ = type(obj)
        module = type_.__module__
        qualname = type_.__qualname__

    return qualname if module in ('typing', 'builtins') else '{}.{}'.format(module, qualname)
