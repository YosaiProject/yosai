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
