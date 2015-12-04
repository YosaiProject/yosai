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

import threading
import time


class StoppableScheduledExecutor(threading.Thread):
    def __init__(self, my_func, interval):
        super().__init__()
        self.event = threading.Event()
        self.my_func = my_func
        self.interval = interval  # in seconds

    def stop(self):
        self.event.set()
        self.join()

    def run(self):
        while True:
            self.my_func()
            if self.event.wait(self.interval):
                return

# yosai.core.omits ThreadContext because it is replaced by the standard library
# threading.local() object
