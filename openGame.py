#Protocol references:
#http://www.rasterbar.com/products/libtorrent/udp_tracker_protocol.html
#http://xbtt.sourceforge.net/udp_tracker_protocol.html
'''
TODO/reference:
-Use STUN to determine external IP: http://tools.ietf.org/html/rfc5389 , http://www.stunprotocol.org/
-Move over to new selectors module: https://docs.python.org/3/library/selectors.html
'''

import socket
import string
import random
import select
import time
import urllib.request
#import tkinter as tk Not needed until GUI

#Functions:
#----------

#A function to initialize everything
def Initialize():
    global peerList, connList, dest, udpPort, tcpPort, s, myIP, notConnected, connecting, connected, verboseMode
    global incomingConnection, outgoingConnection, updatesPerSecond, mainSocket
    peerList = []
    connList = []

    #Some variables to make life easier
    notConnected = 0
    connecting = 1
    connected = 2

    verboseMode = False
    incomingConnection = True
    outgoingConnection = False

    #Set the updates per second value
    updatesPerSecond = 5
    
    #dest = ("open.demonii.com", 1337)
    #backups
    dest = ("tracker.coppersurfer.tk", 6969)
    #dest = ("tracker.leechers-paradise.org", 6969)
    #dest = ("exodus.desync.com", 6969)
    #dest = ("9.rarbg.me", 2710)

    #Create UDP Socket
    #Used for tracker announcing TODO: also as workaround if TCP fails 
    udpPort = 5000
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("", udpPort))

    #Create TCP server socket
    #Used to facilite connection with peers
    tcpPort = 5001
    mainSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mainSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mainSocket.bind(("", tcpPort))
    
    mainSocket.listen(5)

    #Append the main socket to the connection list
    connList.append(mainSocket)

    #Determine our public IP address so we recognize ourselves in an IP list
    #TODO: Eventually needs to use STUN servers
    try:
        #myIP = urllib.request.urlopen("http://ipecho.net/plain").read().decode("utf-8")
        myIP = "174.109.48.176"
    except:
        #myIP = input("The online IP service failed to respond, please manually enter your ip.\n")
        myIP = "174.109.48.176"
    print(myIP)


#This function will output to the console depending on set verbosity level
def alert(verbose, nonverbose =""):
    if verboseMode:
        print(verbose)
    elif nonverbose:
        print(nonverbose)


#A function to announce to trackers
def Announce():
    #Prepare payload
    a = 0x1.to_bytes(4, 'big') #action
    transID = random.randrange(65535).to_bytes(4, 'big') #TransID
    iH = 'opnGameGroundContro4'.encode('ascii')
    myID = ('openGame'+''.join(random.choice(string.ascii_letters + string.digits) for _ in range(12))).encode('ascii')
    d = 0x0.to_bytes(8, 'big')
    l = 0x987.to_bytes(8, 'big')
    u = 0x0.to_bytes(8, 'big')
    e = 0x2.to_bytes(4, 'big') #Event = started
    i = 0x0.to_bytes(4, 'big') #Use default: sender's IP
    k = random.randrange(65535).to_bytes(4, 'big') #Randomized key. No idea why.
    n = (-1).to_bytes(4, 'big', signed=True) #Max peers in response. Uses tracker defaults, will need to gain all somehow

    payload = b"".join([connID + a + transID + iH + myID + d + l + u + e + i + k + n + tcpPort.to_bytes(2, 'big')])

    #Diagnostics
    alert(payload)

    s.sendto(payload, dest)
    
    alert("Announced to tracker.", "Announced to tracker.")


#A function to index returned addresses into the peerlist
#Used to initialize an empty peerlist
def indexAddresses(rawAddr):
    for i in range(len(rawAddr)//6):
        #Older method of doing things
        #a = ".".join([str(int.from_bytes([rawAddr[i]], 'big')), str(int.from_bytes([rawAddr[i+1]], 'big')), str(int.from_bytes([rawAddr[i+2]], 'big')), str(int.from_bytes([rawAddr[i+3]], 'big'))])
        a = socket.inet_ntoa(rawAddr[i:i+4])
        p = int.from_bytes(recvData[24:26], 'big')
        peerList.append([a, p, notConnected, [0]])

    print(peerList)


#A function to set the status of a peer in the list.
#Will add an address into the peerlist if it doesn't already exist.
def setPeerStatus(addr, status):
    e = True

    #Brief search to see if the peer is currently in our list
    for i, (a, b, c, d) in enumerate(peerList):
        if (a, b) == addr:
            alert("Peer " + str(addr) + " already exists in the peer list.")

            #Record the peer's position and toggle flag so peer is not added
            pos = i
            e = False


    
    if e:
        #Add peer into the peerlist
        peerList.append([addr[0], addr[1], status, []])
        alert('Added to peerlist.', 'Added to peerlist.')
    else:
        #Edit the peer's status
        #Somehow this feels like a hack - double check to make sure this doesn't break stuff
        #This will eventually need to reset the context-sensitive variables when the status changes
        if status == notConnected:
            a = 30 #Setting a new timeout
        else:
            a = peerList[pos][3]
        
        peerList[pos] = [peerList[pos][:2], status, a]
    if status == notConnected:
        alert("Peer at " + str(addr) + " set to not connected.", "Peer at " + str(addr) + " set to not connected.")
    elif status == connecting:
        alert("Peer at " + str(addr) + " set to connecting.", "Peer at " + str(addr) + " set to connecting.")
    else:
        alert("Peer at " + str(addr) + " set to connected.", "Peer at " + str(addr) + " set to connected.")
            


#A Potentially pointless function to connect to peers
def peerConnection(incom, address = ""):
    if incom:
        #Handle the new incoming connection
        peerSock, peerAddr = mainSocket.accept()
        print('Accepted a connection from ' + str(peerAddr))
        setPeerStatus(peerAddr, connected)

        #Add to the connection list
        connList.append(peerSock)

        #Debug data
        alert("New connection list: " + str(connList))
    else:
        #Create a new outgoing connection
        #Until STUN servers can be implemented
        peerSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #peerSock.setblocking(False)
        print('Attempting a connection to ' + str(address))
        peerSock.settimeout(5)
        try:
            peerSock.connect(address)
            setPeerStatus(address, connecting)
        except:
            print('connection failed, waiting 30s to reconnect')
            setPeerStatus(address, notConnected)
        

#The main manager loop
def runManager():
    #A variable to indicate when to stop
    goOn = True

    #Inform the user on program exit
    print('Connection manager is now running. \nPress enter to close this program at any time')
    #TODO: Make the above actually work

    #Manage peer list
    while goOn:
        deltaTime = 1/updatesPerSecond

        #Here, we will loop over all peers, updating and connecting, etc
        #We loop over a shallow copy, because (insert valid reason)
        for i, (a, b, connStatus, connStorage) in enumerate(peerList[:]):
            #Handle all unconnected peers
            #Unconnected peer storage is as follows:
            #0 : Reconnect timeout
            #1 : Total time disconnected

            #None of anything applies to our own ip, so skip
            if a != myIP:
                #print(a)
                #print(myIP)
                if connStatus == notConnected:
                    t = connStorage[0] #The first stored variable is the timeout
                    
                    if t < 0:
                        #Reconnect when timeout below zero
                        peerConnection(outgoingConnection, (a, b))

                    else:
                        #Decrease the reconnect timer
                        peerList[i] = [a, b, connStatus, [t-deltaTime]]

                
            


                    
        #Watch all sockets
        #TODO: Rewrite using the new selectors module
        rSock, w, e = select.select(connList,[],[], 0)
        for s in rSock:
            print('sockets to read')
            #Handle new incoming connections
            if s == mainSocket:
                peerConnection(incomingConnection)

            #Handle incoming data
            else:
                print('Some other socket!')
                TODO = True

        #This loop sleeps so that we will run the loop approx
        #uPS times per second
        time.sleep(1/updatesPerSecond)
    



Initialize()
alert("Initialized. Verbose mode enabled.", "Initialized. Verbose mode disabled.")


#Create connection request
transID = random.randrange(65535).to_bytes(4, 'big')
data = 0x41727101980.to_bytes(8, 'big')+0x0.to_bytes(4, 'big')+transID

alert(data, "Connecting to tracker" + str(dest[0]) + " on port " + str(dest[1]) + ".")

#Send data
s.sendto(data, dest)

#Decode response
#------------------------
recvData, addr = s.recvfrom(1024)

#Perform integrity checks and
#Announce if response checks out
if len(recvData) > 15:
    if transID == recvData[4:8]:
        if 0x0.to_bytes(4, 'big') == recvData[:4]:
            #Store connection ID and announce
            alert(recvData, "Response recieved. Announcing...")   
            connID = recvData[8:16]
            alert(connID)
            Announce()
        else:
            print("Received action is incorrect")

    else:
        print("Received TransID is incorrect")
        print(transID)
        print(recvData[4:8])

else:
    print("Response too short")

#Decode announce response
#------------------------
recvData, addr = s.recvfrom(1024)
alert(recvData)
if len(recvData) > 19:
    #TODO: check action, etc, blahblah
    alert("Reannounce interval: " + str(int.from_bytes(recvData[8:12], 'big')) + " seconds")
    indexAddresses(recvData[20:])
else:
    print("Announce response is too short")


#Enter the main management loop
#------------------------------
runManager()

















