import threading
import time


class StoppableExecutor(threading.Thread):
    def __init__(self, my_func, time_period):
        super().__init__()
        self.event = threading.Event()
        self.my_func = my_func
        self.time_period = time_period  # in seconds
        
    def stop(self):
        self.event.set()
        self.join()

    def run(self):
        while True:
            self.my_func() 
            if self.event.wait(self.time_period):
                return
