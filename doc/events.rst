Event-Driven Architecture
=========================
Yosai features an event-driven architecture whereby events emitted during
authentication, authorization, and session management trigger subsequent
processing.

Events are communicated using a publish-subscribe paradigm whereby
a producer of an event emits the event to a channel (an internal Event Bus) that
relays the event to consumers who have subscribed to the event's topic. The EventBus
is a singleton shared throughout the running instance of Yosai.

image:  http://pubsub.sourceforge.net/_images/pubsub_concept.png

An EventBus relays published events to event subscribers and provides a mechanism for
registering and unregistering event subscribers. With this pubsub paradigm,
components can publish or consume events without tightly coupling consumers to
producers.  This promotes flexibility through loose coupling and high cohesion
between components, leading to a more pluggable architecture.

    Sending Events
    -----------------
    If a component wishes to publish events to other components:::

        event_bus.publish(topic, *kwargs)

    The event bus dispatches the event 'message' to components that wish to receive
    events of that type (known as subscribers).

    Receiving Events
    ------------------
    A component can receive events of interest by doing the following.

    For each event topic you wish to consume, create a callback method
    that will be called when an specific type of event is communicated across
    the event bus.  Register the callback with the event_bus:::

       event_bus.register(topic, callback)


    The following events are currently used in Yosai:

    | :Event Topic             |
    |--------------------------|
    | SESSION.START            |
    | SESSION.STOP             |
    | SESSION.EXPIRE           |
    | AUTHENTICATION.SUCCEEDED |
    | AUTHENTICATION.FAILED    |
    | AUTHORIZATION.GRANTED    |
    | AUTHORIZATION.DENIED     |
    | AUTHORIZATION.RESULTS    |



Event Logging
=============

Before logging events, event payloads are reduced to serializable form using ``marshmallow``.
It is recommended that you format the logged events in a structured manner, such
as by using JSON encoding.  Communicating events in a structured format facilitates
processing of log entries by surveillance systems downstream from Yosai.
With this given, Yosai includes an optional logging module that features JSON
encoded formatting.
