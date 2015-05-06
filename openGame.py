#Protocol references:
#http://www.rasterbar.com/products/libtorrent/udp_tracker_protocol.html
#http://xbtt.sourceforge.net/udp_tracker_protocol.html
'''
TODO/reference:
-Use STUN to determine external IP: http://tools.ietf.org/html/rfc5389 , http://www.stunprotocol.org/
-Move over to new selectors module: https://docs.python.org/3/library/selectors.html
'''
#Next Task: move to selectors module (uses callbacks), finish properly recording connected peers

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
    global peerList, connList, connID, dest, udpPort, tcpPort, s, myIP, notConnected, connecting, connected, \
    verboseMode, incomingConnection, outgoingConnection, updatesPerSecond, mainSocket, readable, writable, \
    recvData
    
    peerList = []
    connList = [[], []]

    #This is a persistent identifier that we need to track
    connID = b""

    #Some variables to make life easier
    notConnected = 0
    connecting = 1
    connected = 2
    readable = 0
    writable = 1

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
    #Used to facilitate connection with peers
    tcpPort = 5001
    mainSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mainSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mainSocket.bind(("", tcpPort))
    
    mainSocket.listen(5)

    #Append the main socket to the readable subset of the connection list
    connList[readable].append(mainSocket)

    #Determine our public IP address so we recognize ourselves in an IP list
    #TODO: Eventually needs to use STUN servers
    try:
        #myIP = urllib.request.urlopen("http://ipecho.net/plain").read().decode("utf-8")
        myIP = "174.109.48.176"
    except:
        myIP = input("The online IP service failed to respond, please manually enter your ip.\n")
    alert(myIP)


#This function will output to the console depending on set verbosity level
def alert(verbose, nonverbose =""):
    if verboseMode or nonverbose == "_all":
        print(verbose)
    elif nonverbose:
        print(nonverbose)

#This function completely handles making connection to a tracker
def trackerConnect(destAddress):
    global connID   #This fixes a strange bug that creeped in somewhere. TODO: Investigate further.
    transID = random.randrange(65535).to_bytes(4, 'big')
    data = 0x41727101980.to_bytes(8, 'big') + 0x0.to_bytes(4, 'big') + transID

    alert(data, "Connecting to tracker " + str(destAddress[0]) + " on port " + str(destAddress[1]) + ".")
    s.sendto(data, destAddress)

    #Decode response
    #------------------------
    #TODO: make this select based, and give user option to wait or move on if response is slow
    recvData, addr = s.recvfrom(1024)

    #Perform integrity checks and
    #Return True if response checks out
    if len(recvData) > 15:
        if transID == recvData[4:8]:
            if 0x0.to_bytes(4, 'big') == recvData[:4]:
                #The response is valid
                alert("Response: " + str(recvData), "Connection to tracker completed.")   
                connID = recvData[8:16]
                alert("Connection ID: " + str(connID))
                return True
            else:
                alert("Received action is incorrect in the tracker's response.", "_all")
        else:
            alert("Received Transaction ID is incorrect in the tracker's response.", "_all")
            alert("Wanted: " + transID + " Received: " + recvData[4:8], "_all")
    else:
        alert("Response too short", "_all")

    #If we didn't return earlier, the response is bad
    return False


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
    alert("Announced to tracker.", "_all")


#A function to index returned addresses into the peerlist
#Used to initialize an empty peerlist
def indexAddresses(rawAddr):
    for i in range(len(rawAddr)//6):
        #Older method of doing things
        #a = ".".join([str(int.from_bytes([rawAddr[i]], 'big')), str(int.from_bytes([rawAddr[i+1]], 'big')), str(int.from_bytes([rawAddr[i+2]], 'big')), str(int.from_bytes([rawAddr[i+3]], 'big'))])
        a = socket.inet_ntoa(rawAddr[i:i+4])
        p = int.from_bytes(recvData[24:26], 'big')
        peerList.append([a, p, notConnected, [0]])

    #Diagnostics
    alert(peerList)


#A function to set the status of a peer in the list.1
#Will add an address into the peerlist if it doesn't already exist.
def setPeerStatus(addr, status):
    addPeer = True

    #Brief search to see if the peer is currently in our list
    for i, (a, b, c, d) in enumerate(peerList):
        if (a, b) == addr:
            alert("Peer " + str(addr) + " already exists in the peer list.", "_all")

            #Record the peer's position and toggle flag so peer is not added
            pos = i
            addPeer = False

    
    if addPeer:
        #Add peer into the peerlist
        peerList.append([addr[0], addr[1], status, [0]])
        alert('Added to peerlist.', "_all")
    else:
        #Edit the peer's status
        #Somehow this feels like a hack - double check to make sure this doesn't break stuff
        #This will eventually need to reset the context-sensitive variables when the status changes
        if status == notConnected:
            a = 30 #Setting a new timeout
        else:
            a = peerList[pos][3]    #Preserves the existing storage
        
        peerList[pos] = [peerList[pos][0], peerList[pos][1], status, a]
    if status == notConnected:
        alert("Peer at " + str(addr) + " set to not connected.", "_all")
    elif status == connecting:
        alert("Peer at " + str(addr) + " set to connecting.", "_all")
    else:
        alert("Peer at " + str(addr) + " set to connected.", "_all")
            


#A Potentially pointless function to connect to peers
def peerConnection(incom, address = ""):
    if incom:
        #Handle the new incoming connection
        peerSock, peerAddr = mainSocket.accept()
        alert('Accepted a connection from ' + str(peerAddr), "_all")
        setPeerStatus(peerAddr, connected)

        #Add to the connection list
        connList[readable].append(peerSock)

        #Debug data
        alert("New connection list: " + str(connList))
    else:
        #Create a new outgoing connection
        #Until STUN servers can be implemented
        peerSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        peerSock.setblocking(False)
        alert('Attempting a connection to ' + str(address), "_all")
        #The connect will give an error since it cannot instantly complete
        #Add it to the writables list to tell when the connect finishes
        try:
            peerSock.connect(address)
        except:
            pass
        connList[writable].append(peerSock)
        setPeerStatus(address, connecting)
        

#The main manager loop
def runManager():
    #A variable to indicate when to stop
    goOn = True

    #Inform the user on program exit
    print('Connection manager is now running. \nPress enter to close this program at any time')
    #TODO: Make the above actually work

    while goOn:
        deltaTime = 1/updatesPerSecond

        #Manage peer list
        #---------------------------------
        #Here, we will loop over all peers, updating and connecting, etc
        #We loop over a shallow copy, because (insert valid reason)
        for i, (a, b, connStatus, connStorage) in enumerate(peerList[:]):
            #Handle all unconnected peers
            #Unconnected peer storage is as follows:
            #0 : Reconnect timeout
            #1 : Total time disconnected

            #None of anything applies to our own ip, so skip
            if a != myIP:
                if connStatus == notConnected:
                    t = connStorage[0] #The first stored variable is the timeout
                    
                    if t < 0:
                        #Reconnect when timeout below zero
                        peerConnection(outgoingConnection, (a, b))

                    else:
                        #Decrease the reconnect timer
                        peerList[i] = [a, b, connStatus, [t-deltaTime]]

        #Manage all sockets
        #---------------------------------
        #TODO: Rewrite using the new selectors module
        rSock, wSock, e = select.select(connList[0],connList[1],[], 0)
        for s in rSock:
            alert('New socket(s) available to read.')
            #Handle new incoming connections
            if s == mainSocket:
                peerConnection(incomingConnection)

            #Handle incoming data
            else:
                print('Some other socket!')

                #TEMPORARY
                #Read from the socket and dump to console
                recvData, addr = s.recvfrom(1024)
                print(recvData)

        for s in wSock:
            alert('New connections completed.')
            #Set peers to connected state, etc

        #This loop sleeps so that we will run the loop approx
        #uPS times per second
        time.sleep(1/updatesPerSecond)
    


#--Main program sequence--
#-------------------------
Initialize()
alert("Initialized. Verbose mode enabled.", "Initialized. Verbose mode disabled.")


#Connect to our tracker of choice, and announce if it succeeds
if trackerConnect(dest):
    #Store connection ID and announce
    Announce()



#Decode announce response
#------------------------
recvData, addr = s.recvfrom(1024)
alert("Announce response: " + str(recvData))
if len(recvData) > 19:
    #TODO: check action, etc, blahblah
    alert("Reannounce interval: " + str(int.from_bytes(recvData[8:12], 'big')) + " seconds")
    indexAddresses(recvData[20:])
else:
    print("Announce response is too short")


#Enter the main management loop
#------------------------------
runManager()

















