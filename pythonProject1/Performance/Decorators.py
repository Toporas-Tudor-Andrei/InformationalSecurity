import time
from functools import wraps


def time_it(func):
    """
    Decorator function that tracks the time of execution of the function that it decorates
    :param func: function to be decorated
    :return: a tuple of length 2 containing the execution time and the result of the function
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func.__func__(*args, **kwargs)
        end = time.time()
        execution_time = (end - start) * 1000
        print(f"Function '{func.__func__.__name__}' executed in {execution_time:.2f} ms")
        return execution_time, result

    return wrapper
