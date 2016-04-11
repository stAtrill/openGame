import socket, threading, queue, time, os

def start():
    a = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    a.bind(("", 8080))
    a.set_inheritable(True)

    b = queue.Queue()

    thread = threading.Thread(target=abc, args=(a.detach(),))
    thread.start()
    
    time.sleep(5)
    print("From main thread: " + str(a) + "\n")

def abc(c):
    sock = socket.socket(fileno=c)
    for _ in range(6):
        print("Passed as an argument:")
        print(sock)
        
        print("=====================")
        
        time.sleep(1)

start()