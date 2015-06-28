#Protocol references:
#http://www.rasterbar.com/products/libtorrent/udp_tracker_protocol.html
#http://xbtt.sourceforge.net/udp_tracker_protocol.html
#
#WMI references:
#http://timgolden.me.uk/python/wmi/cookbook.html
#http://timgolden.me.uk/python/wmi/index.html
#http://stackoverflow.com/questions/7580834/script-to-change-ip-address-on-windows
#
#Helpful:
#https://community.openvpn.net/openvpn/ticket/316
'''
TODO/reference:
-Use STUN to determine external IP: http://tools.ietf.org/html/rfc5389 , http://www.stunprotocol.org/
-Use upnp to open ports, implement miniUPnP https://github.com/miniupnp/miniupnp/blob/master/miniupnpc/pymoduletest.py
-Detecting failed connections
-Send address, even if unknown, also configure adapter
-UDP tunnel: needs to use data port, not TCP negotiated port
-Move routingTools init to after TunTap init, make routingTools upnp synchronous
-Bug: Crash when announcing address to connecting peer
-Debug adapter crash. Potentially useful resource: http://www.flounder.com/asynchexplorer.htm
'''
#Peer management: Management of timeouts on failed connections

import socket, string, random, select, time, struct, math, urllib.request, signal, binascii

#These are all needed for the TunTapWin class
import win32file
import pywintypes
import win32event
import win32api
import winreg as reg

#These are for the routing manager class
import wmi

import queue, threading
#import tkinter as tk Not needed until GUI

#Functions:
#----------

#A function to initialize everything
def Initialize():
    global peerList, connList, connID, dest, udpPort, tcpPort, dataSocket, notConnected, connecting, connected, removed, \
    verboseMode, incomingConnection, outgoingConnection, updatesPerSecond, mainSocket, readable, writable, \
    recvData, settings, settingsFormatString, myIP, myIPtimestamp, useTUNTAPAutosetup, useBackupBroadcastDectection, \
    loopbackSocket, ethernetMTU, read, write, internalManagementIdentifier, myTcpUdpMode, UdpMode, TcpMode
    
    peerList = []
    connList = [[], []]
    settings = [0, 0, 0]       #[publicIP, timestamp, tunnelMode (TCP or UDP)]

    #Some settings
    verboseMode = False
    settingsFormatString = "4sI?" #4 chars (1 byte apiece), unsigned integer (4 bytes), boolean (1 byte)
    ethernetMTU = 1500
    internalManagementIdentifier = "OpenGame"
    #connectionRetryCount = 0    #Never retry a connection, until the program properly handles timeouts

    #This is a persistent identifier that we need to track
    connID = b""

    #Some variables to make life easier
    notConnected = 0
    connecting = 1
    connected = 2
    removed = 3
    
    readable = 0
    writable = 1
    
    read = 0
    write = 1
    
    UdpMode = 0
    TcpMode = 1
    
    #These are for the settings list
    myIP = 0
    myIPtimestamp = 1
    myTcpUdpMode = 2
    
    #Should the TUNTAP module set itself up?
    useTUNTAPAutosetup = True
    #This uses an alternate method for detecting broadcasts (on WIN 7/8) if the TAP device isn't picking them up
    #If the device is picking them up, it shouldn't be used or every broadcast will be dealt with twice
    useBackupBroadcastDectection = False
    loopbackSocket = 0
    
    incomingConnection = True
    outgoingConnection = False
    
    staleIPtimeout = 21600      #6 hours

    #Set the updates per second value
    updatesPerSecond = 100
    
    dest = ("open.demonii.com", 1337)
    #backups
    #dest = ("tracker.coppersurfer.tk", 6969)
    #dest = ("tracker.leechers-paradise.org", 6969)
    #dest = ("exodus.desync.com", 6969)
    #dest = ("9.rarbg.me", 2710)
    
    #Create TCP server socket
    #Used to facilitate connection with peers
    tcpPort = 5000
    mainSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mainSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mainSocket.bind(("", tcpPort))
    
    mainSocket.listen(5)
    
    #Append the main socket to the readable subset of the connection list
    connList[readable].append(mainSocket)
    
    #Create UDP Socket
    #Used for tracker announcing and UDP tunnel mode
    udpPort = 5000
    dataSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dataSocket.bind(("", udpPort))
    
    #Append the data socket to the readable subset of the connection list if mode is UDP
    if settings[myTcpUdpMode] == UdpMode: connList[readable].append(dataSocket)


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
            a, b, c = struct.unpack(settingsFormatString, sttngFile)

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
        self.trimEthnHeaders = False
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
            if (self.myInterface):
                self.setMediaConnectionStatus(True) 
            else:
                alert("Failed to interface with TAP adapter. Exiting in 5 seconds.", "_all")
                time.sleep(5)
                sys.exit()
            
            self.dataThreads.append(threading.Thread(target=self.dataListenerThread, args=(self.readDataQueue,), daemon = True))
            self.dataThreads.append(threading.Thread(target=self.dataWriterThread, args=(self.writeDataQueue,), daemon = True))
            self.dataThreads[0].start()
            alert('Data listener thread started as daemon.', '_all')
            self.dataThreads[1].start()
            alert('Data injector thread started as daemon.', '_all')
            
    
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
            try:
                self.readResult = win32file.ReadFile(self.myInterface, self.readBuffer, self.overlapped[read])
                win32event.WaitForSingleObject(self.overlapped[read].hEvent, win32event.INFINITE)
            except:
                print("Device malfunctioned during read operation. Attempting to continue...")
                continue

            #MAC Address autodiscover
            #WORKAROUND: If our own MAC hasn't yet been discovered, auto-set it now
            if not self.myMACaddr:
                self.myMACaddr = bytes(self.readResult[1][6:12])
                alert("MAC address auto-discovered: " + str(self.myMACaddr), '_all')
                    
            #Truncate to the actual data - only for IP Packets
            #This functionality has been hacked, this needs to be redone to work properly
            if bytes(self.readResult[1][12:14]) == b"\x08\x00" :
                self.dataLen = int.from_bytes(self.readResult[1][16:18], 'big')
                resultsQueue.put(bytes(self.readResult[1][14*self.trimEthnHeaders:14+self.dataLen]))
            elif bytes(self.readResult[1][12:14]) == b"\x08\x06":
                print("ARP packet detected on adapter")
                self.dataLen = 28       #ARP on IPv4 are always 28 bytes long
                resultsQueue.put(bytes(self.readResult[1][14*self.trimEthnHeaders:14+self.dataLen]))
            else:
                alert('Non-IP/ARP packet was discarded. EtherType code: ' + str(bytes(self.readResult[1][12:14])))
    
    def dataWriterThread(self, toWriteQueue):
        while True:
            if not toWriteQueue.empty():
                if self.trimEthnHeaders:
                    #Add Ethernet header back onto the packet (since it was removed)
                    self.d = self.myMACaddr + self.remoteMACaddr + b"\x08\x00"  #Because, as of right now, this only carries ipv4 traffic
                else:
                    self.d = b""
                alert('Injecting packet on adapter')
                win32file.WriteFile(self.myInterface, self.d + toWriteQueue.get(), self.overlapped[write])
                win32event.WaitForSingleObject(self.overlapped[write].hEvent, win32event.INFINITE)
            else:
                time.sleep(0.05)
    
    def deviceHasData(self):
        if not self.readDataQueue.empty():
            return self.readDataQueue.qsize()
        else:
            return False
    
    #This function updates the IP address and mask of the adapter
    def setDeviceProperties(self, myIP, myMask):
        if not self.myMACaddr:
            print("Mac address not known, cannot set device yet")
            return False
        else:
            a= wmi.WMI()
            for interface in a.Win32_NetworkAdapterConfiguration(IPEnabled=1):
                b = binascii.unhexlify(interface.MACAddress.replace(':', ''))
                if b == self.myMACaddr:
                    c = interface.EnableStatic(IPAddress=[myIP],SubnetMask=[myMask]) 
                    if c[0] == 0:
                        print("IP Address of interface successfully set.")
                        return True
                    elif c[0] < 0: 
                        print("IP Address of interface was not successfully set: Administrator privileges are required to configure the interface.")
                        return False
                    else:
                        print("IP Address of interface was not successfully set: The operation failed with error number: " + str(c[0]))
                        return False
            else:
                print("IP Address of interface was not successfully set: could not find interface.")
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
def shutdown(*args):
    #Write all settings to file
    #---------------------------
    with open('openGame settings', 'wb') as sttngFile:
        sttngFile.write(struct.pack(settingsFormatString, socket.inet_aton(settings[myIP]), settings[myIPtimestamp], settings[myTcpUdpMode]))

    #Close all open sockets (skipping the server socket)
    #---------------------------------------------------
    for sock in connList[readable][1:] + connList[writable]:
        if sock != dataSocket:
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()
        
    alert('Shutdown complete. Exiting...', '_all')

#This function completely handles making connection to a tracker
def trackerConnect(destAddress):
    global connID   #This fixes a strange bug that creeped in somewhere. TODO: Investigate further.
    transID = random.randrange(65535).to_bytes(4, 'big')
    data = 0x41727101980.to_bytes(8, 'big') + 0x0.to_bytes(4, 'big') + transID

    alert(data, "Connecting to tracker " + str(destAddress[0]) + " on port " + str(destAddress[1]) + ".")
    dataSocket.sendto(data, destAddress)

    #Decode response
    #------------------------
    #TODO: make this select based, and give user option to wait or move on if response is slow
    recvData, addr = dataSocket.recvfrom(ethernetMTU)

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
    iH = 'opnGameGroundContro2'.encode('ascii')
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
    
    dataSocket.sendto(payload, dest)
    alert("Announced to tracker.", "_all")

#A function to index returned addresses into the peerlist
#Used to initialize an empty peerlist
def indexAddresses(rawAddr):
    for i in range(len(rawAddr)//6):
        #Older method of doing things
        #a = ".".join([str(int.from_bytes([rawAddr[i]], 'big')), str(int.from_bytes([rawAddr[i+1]], 'big')), str(int.from_bytes([rawAddr[i+2]], 'big')), str(int.from_bytes([rawAddr[i+3]], 'big'))])
        a = socket.inet_ntoa(rawAddr[i:i+4])
        p = int.from_bytes(recvData[24:26], 'big')
        
        #Don't add an address to the list if it is ours
        if a != settings[myIP]:
            peerList.append([a, p, notConnected, [0, None]])

    #Diagnostics
    print("Peerlist: \n"+str(peerList))

#A function to set the status of a peer in the list.
#Will add an address into the peerlist if it doesn't already exist.
def setPeerStatus(addr, status, peerSock = None):

    #Brief search to see if the peer is currently in our list, adding it if not
    pos = 0     #We initiate pos here to handle the case where the peerlist is empty
    for pos, (a, b, c, d) in enumerate(peerList):
        if (a, b) == addr:
            alert("Peer " + str(addr) + " already exists in the peer list.")
            break
    else:
        if status != removed:
            #Add peer into the peerlist, tracking both the address and socket
            peerList.append([addr[0], addr[1], status, [peerSock, None]])
            alert('Added to peerlist.', "_all")
            alert(peerSock)
        else:
            alert('The peer was not found in the peerlist to remove.', "_all")

        
    #Edit the peer's status
    if status == removed:
        peerList.pop(pos)   #Remove the position from the list
        
    else:
        if status == notConnected:
            a = 30 #Setting a new timeout
            
        elif status == connecting:
            #We store the peer's socket in the storage along with a placeholder for an internal IP address
            a = [peerSock, None]

        else:
            a = peerList[pos][3]    #Preserves the existing storage
            
            #If we know our IP, tell them
            routing.announceMyInternalIP(peerList[pos][3][0])
        
            
        peerList[pos] = [peerList[pos][0], peerList[pos][1], status, a]
    
    #Print diagnostic text
    if status == notConnected:
        alert("Peer at " + str(addr) + " set to not connected.", "_all")
    elif status == connecting:
        alert("Peer at " + str(addr) + " set to connecting.", "_all")
    elif status == connected:
        alert("Peer at " + str(addr) + " set to connected.", "_all")
    elif status == removed:
        alert("Peer at " + str(addr) + " was removed from the peer list.", "_all")

#A potentially pointless function to connect to peers
def peerConnection(incom, address = ""):
    if incom:
        #Handle the new incoming connection
        peerSock, peerAddr = mainSocket.accept()
        alert('Accepted a connection from ' + str(peerAddr), "_all")
        setPeerStatus(peerAddr, connected, peerSock)

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
        setPeerStatus(address, connecting, peerSock)

#These are placed all in one class for legibility, and to reduce function spam
class routingTools:
    def __init__(self):
        #Create the in-use IP list (maximum 254 addresses, 0 will always be reserved for the pretend 'gateway', and 255 broadcast)
        self.addrInUse = []
        for i in range(255):
            self.addrInUse.append(False)
        
        #Reserve the first address (Since it cannot be used) and the second (since it pretends to be our gateway)
        self.addrInUse[0] = True
        self.addrInUse[1] = True
        
        #TODO: Setup the adapter, and determine the internal prefix
        self.prefix = "11.0.0."
        self.netMask = "0111"           #This is used piecemeal; refers to which fields need to be checked as broadcast (for internal use only)
        self.myAddr = len(peerList)+1     #This is an initial heuristic that will be overridden in some circumstances
        self.isAddrSet = False
        
        #Create the readable netmask (we use this version with functions outside of this class)
        self.myMask = ""
        for a in self.netMask:
            if int(a) == False:
                self.myMask += "255."
            else:
                self.myMask += "0."
        else:
            self.myMask = self.myMask[:-1]
        
        #Diagnostics
        print('Routing tools initialized. My internal ip address initialized to :' + self.prefix + str(self.myAddr))
        self.updateMyAddr()
        
    #Function to determine whether or not an address is broadcast
    def isBroadcast(self, addr):
        for i in range(4):
            if int(self.netMask[i]) == True and int(addr[i]) != 255:
                return False        #The address is not a broadcast
        else:
            return True
    
    #Function to add a newly discovered address from a peer
    def addDiscoveredAddr(self, peerSock, intrnlAddr):
        #Yet another shallow copy of peerList, so we can modify peerList without messing up the loop
        for i, a in enumerate(peerList[:]):
            if a[3][0] == peerSock:
                if peerList[i][3][1] != None:
                    print('The peers internal IP has already been set. Re-setting...')
                peerList[i][3][1] = intrnlAddr
                print('Peer at index: ' + str(i) + " now has internal IP address: " + self.prefix + str(intrnlAddr))
                self.updateMyAddr()
                break
                
    #This function will update our internal address if there is enough information to do so
    def updateMyAddr(self):
        addr = 0
        
        if not self.isAddrSet:
            #Reset the address in-use list
            #Reserve the first and second addresses
            self.addrInUse[0] = True
            self.addrInUse[1] = True
            for i in range(2, 255):
                self.addrInUse[i] = False
            
            for a in peerList:
                #If any peers have not yet reported their address to us, we cannot set our IP
                if a[3][1] == None:
                    print("Not able to set internal IP yet.")
                    return False
                else:
                    self.addrInUse[a[3][1]] = True
                
            else:
                #Set our address to the first un-used address
                self.myAddr = self.addrInUse.index(False)
                self.isAddrSet = True
                
                #Update the adapter to match
                myTap.setDeviceProperties(self.prefix + str(self.myAddr), self.myMask)
                
                print("Internal IP has now been set to: " + self.prefix + str(self.myAddr))
                return True
        else:
            print('Address has already been set.')
            return True
    
    #This function will tell a peer our IP address, when we know it
    def announceMyInternalIP(self, peerSock):
        if self.isAddrSet:
            print("Announced internal IP to " + str(peerSock.getpeername()))
            peerSock.sendall(bytes(internalManagementIdentifier + chr(self.myAddr), "utf-8"))
        else:
            print("Announced tentative internal IP to " + str(peerSock.getpeername()))
            peerSock.sendall(bytes(internalManagementIdentifier + chr(self.myAddr), "utf-8"))
    
    def routeAndSend(self, dataToSend):
        #Calculate IPv4 address here to avoid repeated calculation inside the loop
        destAddress = dataToSend[(not myTap.trimEthnHeaders)*14+16:(not myTap.trimEthnHeaders)*14+20]
        
        #Detect ARP packets and handle accordingly
        if not myTap.trimEthnHeaders and dataToSend[12:14] == b"\x08\x06":
            isArp = True
        else:
            isArp = False
        
        for addr, port, status, extra in peerList:
            if status == connected:
                #Check first to see if the packet is a broadcast packet
                #The position we read from changes depending on whether ethernet headers are stripped, so make sure
                #setting is correct in the TUNTAP class
                if self.isBroadcast(destAddress) or isArp:
                    if settings[myTcpUdpMode] == TcpMode:
                        extra[0].sendall(dataToSend)
                        alert("Broadcast data sent to : " + str(extra[0].getpeername()), '_all')
                    else:
                        dataSocket.sendto(dataToSend, (addr, udpPort))      #TODO: Fix using our udp port as peer port
                        alert("UDP broadcast data sent to: (" + str(addr) + ", " + str(port) + ")", '_all')
                else:
                    #Here we send data to a single peer
                    #Search the peerlist for the peer, then send
                    if extra[1] != None:
                        alert("Comparing IPs to send to single peer: " + routing.prefix + str(extra[1]))
                        alert(destAddress)
                        alert(socket.inet_aton(routing.prefix + str(extra[1])))
                        if settings[myTcpUdpMode] == TcpMode:
                                if socket.inet_aton(routing.prefix + str(extra[1])) == destAddress:
                                    extra[0].sendall(dataToSend)
                                    alert("Sent data only to : " + str(extra[0].getpeername()) + ", internal IP: " + str(routing.prefix + extra[1]), '_all')
                        else:
                            if socket.inet_aton(routing.prefix + str(extra[1])) == destAddress:
                                dataSocket.sendto(dataToSend, (addr, udpPort))      #TODO: Fix using our udp port as peer port
                                alert("Sent UDP data only to : (" + str(addr) + ", " + str(udpPort) + "), internal IP: " + routing.prefix + str(extra[1]), '_all')

#The main manager loop
def runManager():
    #A variable to indicate when to stop
    goOn = True
    deltaTime = 1/updatesPerSecond

    #Inform the user on program exit
    print('Connection manager is now running. \nPress CTRL + C to close this program at any time')
    #TODO: Make the above actually work

    while goOn:

        #Manage peer list
        #---------------------------------
        #Here, we will loop over all peers, updating and connecting, etc
        #We loop over a shallow copy, because (insert valid reason) -> we may modify the list inside of this loop
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
        rSock, wSock, e = select.select(connList[readable],connList[writable],[], 0)
        for s in rSock:
            alert('New socket(s) available to read.')
            #Handle new incoming connections
            if s == mainSocket:
                peerConnection(incomingConnection)

            #Handle broadcasts picked up via the loopback socket
            elif s == loopbackSocket:
                alert('Loopback socket has detected a broadcast')
                recvData = s.recv(ethernetMTU)
                alert(str(recvData), '_all')
                routing.routeAndSend(recvData)
            
            #Handle data from the data socket (but only when in UDP mode)
            elif s == dataSocket:
                if settings[myTcpUdpMode] == TcpMode:
                    s.recvfrom(ethernetMTU)     #Discard the data.
                    print("Data discarded")
                else:
                    recvData, addr = s.recvfrom(ethernetMTU)
                    
                    #Diagnostics
                    alert('Incoming UDP data from ' + str(addr), "_all")
                    alert(recvData)
                    
                    #Send packets to the TAP adapter write queue
                    myTap.writeDataQueue.put(recvData)

            else:
                #Receive the data
                #This is in a try block to catch force-closed connection exceptions
                try:
                    recvData, addr = s.recvfrom(ethernetMTU)
                except socket.error:
                    #Connection forcefully closed
                    alert('Connection from ' + str(addr) + ' has forcefully closed. Probable cause: crash', "_all")
                    connList[readable].remove(s)
                    
                    #Diagnostics
                    print("Peername: " + str(s.getpeername()) + ", address: " + str(addr))
                    print(recvData)
                    
                    #Remove the disconnected peer
                    setPeerStatus(s.getpeername(), removed)
                    
                    #Close the socket
                    s.close()
                else:
                    #Diagnostics
                    alert('Incoming data from ' + str(addr))
                    alert(recvData)
                    
                    if recvData[:len(internalManagementIdentifier)] == internalManagementIdentifier.encode():
                        alert('Internal management info received. Peer at ' + str(s.getpeername()) + " has internal IP :" + str(recvData[len(internalManagementIdentifier):]), '_all')
                        routing.addDiscoveredAddr(s, ord(recvData[len(internalManagementIdentifier):].decode("utf-8")))
                    else:
                        #Send packets to the TAP adapter write queue
                        myTap.writeDataQueue.put(recvData)
                

        for s in wSock:
            alert('New connections completed.', '_all')
            #Set peers to connected state, move socket to readable list
            connList[readable].append(s)
            connList[writable].remove(s)
            setPeerStatus(s.getpeername(), connected)
        
        #Check the adapter for data
        if myTap.deviceHasData():
            while myTap.deviceHasData():
                routing.routeAndSend(myTap.readDataQueue.get())

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
else:
    print('Connection to tracker failed. Autoclosing in 5 seconds')
    time.sleep(5)
    sys.exit()

#Decode announce response
#------------------------
recvData, addr = dataSocket.recvfrom(ethernetMTU)
alert("Announce response: " + str(recvData))
if len(recvData) > 19:
    #TODO: check action, etc, blahblah
    alert("Reannounce interval: " + str(int.from_bytes(recvData[8:12], 'big')) + " seconds")
    indexAddresses(recvData[20:])
else:
    print("Announce response is too short")
routing = routingTools()

#Setup shutdown handlers so program gracefully closes
#----------------------------------------------------
#We use the signal module to ensure shutdown, since atexit doesn't execute when closed with signal/message
signal.signal(signal.SIGTERM, shutdown)

#Enter the main management loop
#------------------------------

try:
    runManager()
#So that no traceback is printed for a CTRL+C
except KeyboardInterrupt:
    pass
finally:
    shutdown()





