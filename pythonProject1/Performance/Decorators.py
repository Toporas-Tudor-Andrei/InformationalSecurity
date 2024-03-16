import resource
import time
from functools import wraps


def time_it(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        end = time.time()
        execution_time = (end - start) * 1000
        print(f"Function '{func.__name__}' executed in {execution_time:.2f} ms")
        return execution_time, result

    return wrapper
