import time
import multiprocessing
print("silly")


def my_function():
    time.sleep(1)
    print("my_function is done!")
 
if __name__ == '__main__':
    process = multiprocessing.Process(target=my_function)
    process.start()
    print("__main__ is done!")