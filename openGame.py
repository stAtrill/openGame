#Protocol references:
#http://www.rasterbar.com/products/libtorrent/udp_tracker_protocol.html
#http://xbtt.sourceforge.net/udp_tracker_protocol.html
'''
TODO/reference:
-Use STUN to determine external IP: http://tools.ietf.org/html/rfc5389 , http://www.stunprotocol.org/
-Move over to new selectors module: https://docs.python.org/3/library/selectors.html
-Enable OVERLAPPED property to allow async tuntap use!
'''
#Next Task: move to selectors module (uses callbacks), finish properly recording connected peers
#Peer management: Management of timeouts on failed connections, keep alive

import socket
import string
import random
import select
import time
import urllib.request
import struct
import time
import math
import win32file
import pywintypes
import win32event
import win32api
import winreg as reg
import queue
import threading
#import tkinter as tk Not needed until GUI

#Functions:
#----------

#A function to initialize everything
def Initialize():
    global peerList, connList, connID, dest, udpPort, tcpPort, s, notConnected, connecting, connected, \
    verboseMode, incomingConnection, outgoingConnection, updatesPerSecond, mainSocket, readable, writable, \
    recvData, settings, settingsFormatString, myIP, myIPtimestamp, useTUNTAPAutosetup, useBackupBroadcastDectection, \
    loopbackSocket, ethernetMTU, read, write
    
    peerList = []
    connList = [[], []]
    settings = [0, 0]       #[publicIP, timestamp]

    #Some settings
    verboseMode = False
    settingsFormatString = "4sI"
    ethernetMTU = 1500

    #This is a persistent identifier that we need to track
    connID = b""

    #Some variables to make life easier
    notConnected = 0
    connecting = 1
    connected = 2
    
    readable = 0
    writable = 1
    
    read = 0
    write = 1
    
    #Should the TUNTAP module set itself up?
    useTUNTAPAutosetup = True
    #This uses an alternate method for detecting broadcasts (on WIN 7/8) if the TAP device isn't picking them up
    #If the device is picking them up, it shouldn't be used or every broadcast will be dealt with twice
    useBackupBroadcastDectection = False
    loopbackSocket = 0
    
    incomingConnection = True
    outgoingConnection = False
    
    staleIPtimeout = 21600      #6 hours
    myIP = 0
    myIPtimestamp = 1

    #Set the updates per second value
    updatesPerSecond = 15
    
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


    #Load the settings file, if it exists
    #------------------------
    try:
        #Nothing will happen, and we will just write to the new file on exit
        open('openGame settings', 'x')
        print('Created new settings file.')     #Will never be printed if the file exists
    except FileExistsError:
        try:
            #Load the settings file
            print('Opened settings file')
            sttngFile = open('openGame settings', 'rb').read()
            #Format code: The IP address, and an unsigned int timestamp of when the IP was recorded
            a , b = struct.unpack(settingsFormatString, sttngFile)

            #Update the IP address if the stored one is valid and current
            if int.from_bytes(a, 'big') > 0 and time.time() - b < staleIPtimeout:
                alert("Public IP restored from saved values.", "_all")
                alert("Old IP address is " + str(math.floor(time.time() - b)) + " seconds old.")
                settings[myIP] = socket.inet_ntoa(a)
        except:
            pass    #The unpacking failed for some reason, or the file was otherwise invalid. Oh well.
        

    #Determine our public IP address so we recognize ourselves in an IP list
    #TODO: Eventually needs to use STUN servers
    if settings[myIP] == 0:
        alert("Either saved IP was stale, invalid, or the settings file was just created. Retrieving public IP...")
        try:
            settings[myIP] = urllib.request.urlopen("http://ipecho.net/plain").read().decode("utf-8")
            settings[myIPtimestamp] = math.floor(time.time())
        except:
            settings[myIP] = input("The online IP service failed to respond, please manually enter your public IP.\n")
            settings[myIPtimestamp] = math.floor(time.time())
        alert(settings[myIP])

#This class encapsulates the TUNTAP object (mainly so I can collapse it and not have to look at this cryptic eyesore)
#Even though there were some examples online, they only provided partial functionality, and were exceedingly cryptic
#So this was written as an alternative
class tuntapWin:

    #A useful constant
    adapterKey = r'SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}'
    
    #I would love to find a better way to do these
    #---------------------------------------------
    """By default we operate as a "tap" virtual ethernet
    802.3 interface, but we can emulate a "tun"
    interface (point-to-point IPv4) through the
    TAP_WIN_IOCTL_CONFIG_POINT_TO_POINT or
    TAP_WIN_IOCTL_CONFIG_TUN ioctl."""
    def CTL_CODE(self, device_type, function, method, access):
        return (device_type << 16) | (access << 14) | (function << 2) | method
    def TAP_CONTROL_CODE(self, request, method):
        return self.CTL_CODE(34, request, method, 0)
    #---------------------------------------------
        
    #Returns the GUID of the tap device, or False if it cannot be found
    def getDeviceGUID(self):
        with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, self.adapterKey) as adapters:
            try:
                for i in range(1000):
                    keyName = reg.EnumKey(adapters, i)
                    with reg.OpenKey(adapters, keyName) as adapter:
                        try:
                            componentID = reg.QueryValueEx(adapter, 'ComponentId')[0]
                            if componentID == 'tap0801' or componentID == 'tap0901':
                                return reg.QueryValueEx(adapter, 'NetCfgInstanceId')[0]
                        except WindowsError:
                            pass
            except WindowsError:
                pass
            
            #If no key was found
            alert("Failed to locate a TAP device in the windows registry.", "_all")
            return False
    
    def __init__(self, autoSetup = False):
        #These can be used, or not.
        self.myGUID = ""
        self.myInterface = 0
        self.trimEthnHeaders = True
        self.ethernetMTU = ethernetMTU
        self.myMACaddr = b""            #A workaround, as I haven't figured out how to get the return from the GET_MAC control code
        self.remoteMACaddr = b"\xc4\x15\x53\xb3\x04\x33"    #Basically, when injecting packets, they come from a completely arbitrary address.
        self.readDataQueue = queue.Queue()
        self.writeDataQueue = queue.Queue()
        self.dataThreads = []
        
        #Set up two overlapped structure for async operation, one for reading, the other for writing
        self.overlapped = []
        for i in range(2):
            self.overlapped.append(pywintypes.OVERLAPPED())
            self.overlapped[i].hEvent  = win32event.CreateEvent(None, 0, 0, None)
        self.readBuffer = win32file.AllocateReadBuffer(self.ethernetMTU)
        
        
        #Some function encapsulation
        #In case anyone else reads this, the tap control codes use the windows io control code interface to pass special
        #codes to the tap driver. Also, some constants are borrowed from the win iocontrol library (which are simply replaced with numbers here) 
        self.TAP_IOCTL_GET_MAC =                     self.TAP_CONTROL_CODE(1, 0)
        self.TAP_IOCTL_GET_VERSION =                 self.TAP_CONTROL_CODE(2, 0)
        self.TAP_IOCTL_GET_MTU =                     self.TAP_CONTROL_CODE(3, 0)
        self.TAP_IOCTL_GET_INFO =                    self.TAP_CONTROL_CODE(4, 0)
        self.TAP_IOCTL_CONFIG_POINT_TO_POINT =       self.TAP_CONTROL_CODE(5, 0)        #This call has been obsoleted, use CONFIG_TUN instead
        self.TAP_IOCTL_SET_MEDIA_STATUS =            self.TAP_CONTROL_CODE(6, 0)
        self.TAP_IOCTL_CONFIG_DHCP_MASQ =            self.TAP_CONTROL_CODE(7, 0)
        self.TAP_IOCTL_GET_LOG_LINE =                self.TAP_CONTROL_CODE(8, 0)
        self.TAP_IOCTL_CONFIG_DHCP_SET_OPT=          self.TAP_CONTROL_CODE(9, 0)
        self.TAP_IOCTL_CONFIG_TUN =                  self.TAP_CONTROL_CODE(10, 0)
        
        #Whether the object should attempt to initialize itself
        if autoSetup:
            self.myGUID = self.getDeviceGUID()
            alert("Tap GUID: " + self.myGUID)
            
            self.myInterface = self.createInterface()
            self.setMediaConnectionStatus(True)
            
            self.dataThreads.append(threading.Thread(target=self.dataListenerThread, args=(self.readDataQueue,)))
            self.dataThreads.append(threading.Thread(target=self.dataWriterThread, args=(self.writeDataQueue,)))
            self.dataThreads[0].start()
            alert('Data listener thread started.', '_all')
            self.dataThreads[1].start()
            alert('Data injector thread started.', '_all')
            
    
    #A function to make sure we close our handle and reset media status
    def __del__(self):
        win32file.CloseHandle(self.myInterface)
        self.setMediaConnectionStatus(False)
        print("Handle closed, media disconnected.")
    
    #A function to set the media status as either connected or disconnected in windows
    def setMediaConnectionStatus(self, toConnected):
        win32file.DeviceIoControl(self.myInterface, self.TAP_IOCTL_SET_MEDIA_STATUS, toConnected.to_bytes(4, "little"), None)

    def createInterface(self):
        if self.myGUID == "":
            alert("GUID is empty - the device needs to be identified before calling this function.", "_all")
            return False
        else:
            try:
                return win32file.CreateFile(r'\\.\Global\%s.tap' % self.myGUID,
                                      win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                                      win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
                                      None, win32file.OPEN_EXISTING,
                                      win32file.FILE_ATTRIBUTE_SYSTEM | win32file.FILE_FLAG_OVERLAPPED,
                                      None)
                                      
            except:
                alert("Failed to create interface to TAP device.", "_all")
                return False
    
    #A function to constantly grab data from the tap device, perform some basic filtering, and enter the results in a queue
    def dataListenerThread(self, resultsQueue):
        while True:
            self.readResult = win32file.ReadFile(self.myInterface, self.readBuffer, self.overlapped[read])
            win32event.WaitForSingleObject(self.overlapped[read].hEvent, win32event.INFINITE)

            #MAC Address autodiscover
            #WORKAROUND: If our own MAC hasn't yet been discovered, auto-set it now
            if not self.myMACaddr:
                self.myMACaddr = bytes(self.readResult[1][6:12])
                alert("MAC address auto-discovered: " + str(self.myMACaddr), '_all')
                    
            #Truncate to the actual data - only for IP Packets
            if bytes(self.readResult[1][12:14]) == b"\x08\x00":
                self.dataLen = int.from_bytes(self.readResult[1][16:18], 'big')
                resultsQueue.put(bytes(self.readResult[1][14*self.trimEthnHeaders:14+self.dataLen]))
            else:
                alert('Non-ip packet was discarded. EtherType code: ' + str(bytes(self.readResult[1][12:14])))
    
    def dataWriterThread(self, toWriteQueue):
        while True:
            if not toWriteQueue.empty():
                #Add Ethernet header back onto the packet
                self.d = self.myMACaddr + self.remoteMACaddr + b"\x08\x00"  #Because, as of right now, this only carries ipv4 traffic
                print('Injecting packet on adapter')
                win32file.WriteFile(self.tuntap, self.d + toWriteQueue.get(), self.overlapped[write])
                win32event.WaitForSingleObject(self.overlapped[write].hEvent, win32event.INFINITE)
            else:
                time.sleep(0.05)
    
    def deviceHasData(self):
        if not self.readDataQueue.empty():
            return self.readDataQueue.qsize()
        else:
            return False
                
#This function sets up a backup method for receiving broadcasts on win 7 and 8
#Essentially, binds a raw socket to the loopback interface, and for some magical reason, broadcasts appear
#Reference: https://github.com/dechamps/WinIPBroadcast/blob/master/WinIPBroadcast.c
def initBroadcastLoopbackMethod():
    loopbackSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    loopbackSocket.bind(('127.0.0.1', 1))
    
    #Add to the connection list
    connList[readable].append(loopbackSocket)

#This function will output to the console depending on set verbosity level
def alert(verbose, nonverbose =""):
    if verboseMode or nonverbose == "_all":
        print(verbose)
    elif nonverbose:
        print(nonverbose)

#This function properly shuts down the program
def shutdown():
    #Write all settings to file
    #---------------------------
    with open('openGame settings', 'wb') as sttngFile:
        sttngFile.write(struct.pack(settingsFormatString, socket.inet_aton(settings[myIP]), settings[myIPtimestamp]))

    #Close all open sockets (skipping the server socket)
    #---------------------------------------------------
    for sock in connList[readable][1:] + connList[writable]:
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()

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
    recvData, addr = s.recvfrom(ethernetMTU)

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
    iH = 'opnGameGroundContro1'.encode('ascii')
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

#A potentially pointless function to connect to peers
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

#This function sends data to connected peers! Woohoo!
def routeAndSend(dataToSend):
    #Check first to see if the packet is a broadcast packet
    #The position we read from changes depending on whether ethernet headers are stripped, so make sure
    #setting is correct in the TUNTAP class
    if dataToSend[16:20] == b'\xff\xff\xff\xff':
        for peerSock in connList[readable]:
            if peerSock != mainSocket and peerSock != loopbackSocket:
                peerSock.sendall(dataToSend)
                print("Sent data to : " + str(peerSock.getpeername())) #, '_all')
    else:
        #Here we send data to a single peer
        pass

#The main manager loop
def runManager():
    #A variable to indicate when to stop
    goOn = True

    #Inform the user on program exit
    print('Connection manager is now running. \nPress CTRL + C to close this program at any time')
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

            #Nothing of anything applies to our own IP, so skip
            if a != settings[myIP]:
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

            #Handle broadcasts picked up via the loopback socket
            elif s == loopbackSocket:
                print('Loopback socket has detected a broadcast')
                recvData = s.recv(ethernetMTU)
                alert(str(recvData), '_all')
                routeAndSend(recvData)

            else:
                #Receive the data
                recvData, addr = s.recvfrom(ethernetMTU)
                
                #Diagnostics
                print('Incoming data from ' + str(addr))
                alert(recvData, '_all')
                
                #Send packets to the TAP adapter write queue
                myTap.toWriteQueue.put(recvData)
                

        for s in wSock:
            alert('New connections completed.', '_all')
            #Set peers to connected state, move socket to readable list
            print(connList)
            connList[readable].append(s)
            connList[writable].remove(s)
            print(connList)     #Remove once correct functionality is ensured
            setPeerStatus(address, connected)
        
        #Check the adapter for data
        if myTap.deviceHasData():
            while myTap.deviceHasData():
                routeAndSend(myTap.readDataQueue.get())

        #This loop sleeps so that we will run the loop approx
        #uPS times per second
        time.sleep(1/updatesPerSecond)
    


#--Main program sequence--
#-------------------------
Initialize()
alert("Initialized. Verbose mode enabled.", "Initialized. Verbose mode disabled.")

#Instantiate our tuntap class and have it auto-setup
myTap = tuntapWin(useTUNTAPAutosetup)
alert("Tuntap device initialized, interface created.", "_all")


#Connect to our tracker of choice, and announce if it succeeds
if trackerConnect(dest):
    #Store connection ID and announce
    Announce()



#Decode announce response
#------------------------
recvData, addr = s.recvfrom(ethernetMTU)
alert("Announce response: " + str(recvData))
if len(recvData) > 19:
    #TODO: check action, etc, blahblah
    alert("Reannounce interval: " + str(int.from_bytes(recvData[8:12], 'big')) + " seconds")
    indexAddresses(recvData[20:])
else:
    print("Announce response is too short")


#Enter the main management loop
#------------------------------
try:
    runManager()
except KeyboardInterrupt:
    print('Shutting down...')
    shutdown()





