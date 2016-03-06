"""
Opengame Benchmarks:
>>> timeit.timeit("q.set();q.clear()", "from threading import Event; q = Event()")
2.1774317911330505
>>> timeit.timeit("w.append(1);q.set();w.pop();q.clear()", "from threading import Event; from collections import deque; q = Event(); w = deque()")
2.31834539373385
>>> timeit.timeit("q.put(1);q.get()", "from queue import Queue; q = Queue()")
4.863368441849843
>>> timeit.timeit("q[0].send(1);q[1].recv()", "from multiprocessing import Pipe; q = Pipe()")
15.473005757431793
"""