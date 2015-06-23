# The following classes are derivations of the threading classes provided 
# in the Twitter commons

import threading
import time


class StoppableExecutor(threading.Thread):
    """ 
    A thread that can stop
    """
    def __init__(self, group=None, target=None, name=None, post_target=None, args=(), kwargs=None):
        if kwargs is None:
            kwargs = {}

        def stoppable_target():
            while True:
                target(**kwargs)
                with self.my_lock:  # context manager acquires and releases
                    if self.is_stopped:
                        return

        super().__init__(group=group, target=stoppable_target, name=name, args=args, kwargs=kwargs)
        self.my_lock = threading.Lock()
        self.is_stopped = False

    def stop(self):
        """
        stop() blocks until the thread is joined.  All of the objects provided by 
        the Threading module that have acquire() and release() methods can be
        used as context managers for a with statement.  The acquire() method
        will be called when the block is entered, and release() will be called
        when the block is exited.  
        """
        with self.my_lock:  # context manager acquires and releases
            self.is_stopped = True
        self.join()


class ScheduledStoppableExecutor(StoppableExecutor):
    """
    A thread that runs a target function as scheduled
    """
    def __init__(self, group=None, target=None, name=None, time_period=1, args=(), kwargs=None):
        if kwargs is None:
            kwargs = {}

        def scheduled_target():
            target(**kwargs)
            time.sleep(time_period)  # in seconds

        StoppableExecutor.__init__(self, target=scheduled_target, 
                                   name=name, kwargs=kwargs)

