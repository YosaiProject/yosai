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

from abc import ABCMeta, abstractmethod


class EventBus(metaclass=ABCMeta):
    """
    An event bus can publish events to event subscribers as well as provide a
    mechanism for registering and unregistering event subscribers.

    An event bus enables a publish/subscribe paradigm within Yosai -- components
    can publish or consume events they find relevant without needing to be
    tightly coupled to other components.  This affords great flexibility within
    Yosai by promoting loose coupling and high cohesion between components and
    a much safer pluggable architecture.

    Sending Events
    -----------------
    If a component wishes to publish events to other components:::

        event_bus.sendMessage(topic, *kwargs)

    The event bus dispatches the event 'message' to components that wish to receive
    events of that type (known as subscribers).

    Receiving Events
    ------------------
    A component can receive events of interest by doing the following.

    For each event topic you wish to consume, create a callback method
    that will be called when an specific type of event is communicated across
    the event bus.  Register the callback with the event_bus:::

       event_bus.subscribe(topic, callback)

    """

    @abstractmethod
    def sendMessage(self, topic_name, **kwargs):
        pass

    @abstractmethod
    def subscribe(self, _callable, topic_name):
        pass

    @abstractmethod
    def unsubscribe(self, listener, topic_name):
        pass
