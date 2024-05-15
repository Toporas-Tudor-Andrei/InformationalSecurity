import time
from functools import wraps
import memory_profiler


def time_it(func):
    """
    Decorator function that tracks the time of execution of the function that it decorates
    :param func: function to be decorated
    :return: a tuple of length 2 containing the execution time and the result of the function
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        end = time.time()
        execution_time = (end - start) * 1000
        print(f"Function '{func.__name__}' executed in {execution_time:.2f} ms")
        return execution_time, result

    return wrapper


def memory_usage(func):
    """
    Decorator function that tracks the memory usage of the function that it decorates
    :param func: function to be decorated
    :return: a tuple of memory usage and the result of the function
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        m1 = memory_profiler.memory_usage()[0]
        result = func.__func__(*args, **kwargs)
        m2 = memory_profiler.memory_usage()[0]
        memory_usage_kb = (m2 - m1) * 1024
        print(f"Function '{func.__func__.__name__}' used {memory_usage_kb:.2f} KB of memory")
        return memory_usage_kb, result

    return wrapper


def stats(f):
    def wrapper(*args, **kwargs):
        (exec_time, (mem, res)) = time_it(memory_usage(f))(*args, **kwargs)
        return exec_time, mem, res
    return wrapper
