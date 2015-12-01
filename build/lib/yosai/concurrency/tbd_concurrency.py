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

"""
The following classes are related to apache shiro concurrency.
I have no interest in implementing concurrency of any kind 
on day one, except for Session validation.  The non-concurrenty Yosai 
will serve as a benchmark that will be improved on in subsequent releases
through asyncio, multithreading, or whatever.  Any calls to the following
objects will be either removed or revised for non-concurrent processing.
"""
class Callable(object):
    pass


class Runnable(object):
    pass


class SubjectCallable(object):
    pass


class SubjectRunnable(object):
    pass


class Thread(object):
    pass

