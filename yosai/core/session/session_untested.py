class ExecutorServiceSessionValidationScheduler(session_abcs.SessionValidationScheduler):
    """
    Note:  Many data stores support TTL (time to live) as a feature.  It
           is unecessary to run a session-validation/Executor service if
           you can use the TTL timeout feature.

           yosai.core.vs shiro:
           Shiro uses a daemon thread for scheduled validation, signaling
           it when to shutdown.  Python terminates daemon threads much more
           abruptly than Java, so Yosai will not use them.  Instead, Yosai uses
           regular threads and an event notification process to gracefully terminate.
           See:  https://docs.python.org/3/library/threading.html#thread-objects

    """
    def __init__(self, session_manager, interval):
        """
        :param sessionmanager: a ValidatingSessionManager
        :param interval:  a time interval, in seconds
        """
        self.session_manager = session_manager
        self.interval = interval  # in seconds
        self._enabled = False
        self.service = StoppableScheduledExecutor(self.run,
                                                  interval=self.interval)

    @property
    def is_enabled(self):
        return self._enabled

    # StoppableScheduledExecutor validates sessions at fixed intervals
    def enable_session_validation(self):
        if (self.interval):
            self.service.start()
            self._enabled = True

    def run(self):
        msg = "Executing session validation..."
        print(msg)
        # log here

        start_time = int(round(time.time() * 1000, 2))
        self.session_manager.validate_sessions()
        stop_time = int(round(time.time() * 1000, 2))

        msg2 = ("Session validation completed successfully in " +
                str(stop_time - start_time) + " milliseconds.")
        print(msg2)
        # log here

    def disable_session_validation(self):
        self.service.stop()
        self.enabled = False


# yosai.core.refactor:
class ScheduledSessionValidator:
    """
    Use this class if you want to manually control scheduled invalidation
    of sessions.
    """
    def __init__(self, session_handler, session_store):

        self.session_handler = session_handler

        # note:  this session_store requires active_sessions support, which is
        #        not available from a default SessionStore:
        self.session_store = session_store

        self.session_validation_scheduler = None  # setter injected
        self.session_validation_scheduler_enabled =\
            session_settings.validation_scheduler_enable
        self.session_validation_interval =\
            session_settings.validation_time_interval

        self.enable_session_validation_if_necessary()

    def create_session_validation_scheduler(self):
        msg = ("No SessionValidationScheduler set.  Attempting to "
               "create default instance.")
        # log here
        print(msg)

        scheduler = ExecutorServiceSessionValidationScheduler(
            session_manager=self, interval=self.session_validation_interval)

        msg2 = ("Created default SessionValidationScheduler instance of "
                "type [" + scheduler.__class__.__name__ + "].")
        print(msg2)
        # log here:

        return scheduler

    def enable_session_validation_if_necessary(self):
        scheduler = self.session_validation_scheduler
        if (self.session_validation_scheduler_enabled and
           (scheduler is None or (not scheduler.is_enabled))):
            self.enable_session_validation()

    def enable_session_validation(self):
        scheduler = self.session_validation_scheduler
        if (scheduler is None):
            print("Creating session validation scheduler")
            scheduler = self.create_session_validation_scheduler()
            self.session_validation_scheduler = scheduler

        msg = "Enabling session validation scheduler..."
        # log here
        print(msg)

        scheduler.enable_session_validation()
        self.after_session_validation_enabled()

    def after_session_validation_enabled(self):
        pass

    def before_session_validation_disabled(self):
        pass

    def disable_session_validation(self):
        self.before_session_validation_disabled()
        scheduler = self.session_validation_scheduler
        if (scheduler is not None):
            try:
                scheduler.disable_session_validation()
                msg = "Disabled session validation scheduler."
                # log here
                print(msg)

            except:
                msg2 = ("Unable to disable SessionValidationScheduler. "
                        "Ignoring (shutting down)...")
                # log here
                print(msg2)

            self.session_validation_scheduler = None

    def get_active_sessions(self):
        # note:  this requires a SessionStore with active_session support:
        active_sessions = self.session_store.get_active_sessions()
        if (active_sessions is not None):
            return active_sessions
        else:
            return tuple()

    def validate_sessions(self):
        msg1 = "Validating all active sessions..."
        print(msg1)
        # log here

        invalid_count = 0
        active_sessions = self.get_active_sessions()
        print('\n\nactive sessions: ', active_sessions, '\n\n')
        if (active_sessions):
            for session in active_sessions:
                try:
                    # simulate a lookup key to satisfy the method signature.
                    # self.could probably be cleaned up in future versions:
                    session_key = SessionKey(session.session_id)
                    self.session_handler.validate(session, session_key)
                except InvalidSessionException as ex:
                    expired = isinstance(ex, ExpiredSessionException)
                    msg2 = "Invalidated session with id [{s_id}] ({exp})".\
                           format(s_id=session.get_id(),
                                  exp="expired" if (expired) else "stopped")
                    print(msg2)
                    # log here
                    invalid_count += 1

        msg3 = "Finished session validation.  "
        print(msg3)
        # log here

        if (invalid_count > 0):
            msg3 += "[" + str(invalid_count) + "] sessions were stopped."
        else:
            msg3 += "No sessions were stopped."
        print(msg3)
        # log here

        return msg3
