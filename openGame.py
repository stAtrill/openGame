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
#
#Potentially useful resource: http://www.flounder.com/asynchexplorer.htm
'''
TODO/reference:
-Use STUN to determine external IP: http://tools.ietf.org/html/rfc5389 , http://www.stunprotocol.org/
-Use upnp to open ports, implement miniUPnP https://github.com/miniupnp/miniupnp/blob/master/miniupnpc/pymoduletest.py
-Move routingTools init to after TunTap init, make routingTools upnp synchronous
-Bug: Crash when announcing address to connecting peer if 2 peers trying to connect to each other simultaneously
-Reannounce to trackers - threaded
-Implement NDIS 6 functionality
-Opengame needs to request Admin privileges if it encounters privilege-related errors
-Peer crash causes crash
-Figure out how to propagate metric and tcp changes in registry
==============
-Datalistenerthread should not pass any data if there were errors
-Recent peers
adapt routeAndSend to handle ipv6 traffic
peerexchange
miniupnp
GUI
'''

#A note on structure: the peerlist isn't ever protected with locks, instead this program is designed
#so that the peerlist is ever only accessed from the main thread

import socket, string, random, select, time, struct, math, urllib.request, signal, binascii, os, win32ui, ctypes, sys

#These are all needed for the TunTapWin class
import win32file
import pywintypes
import win32event
import win32api
import winerror
import winreg as reg

#These are for the routing manager class
import wmi

import queue, threading
#import tkinter as tk

#Functions:
#----------

#A function to initialize everything
def Initialize():
    global peerList, connList, connID, dest, udpPort, tcpPort, dataSocket, notConnected, connecting, connected, removed, add, remove,\
    connListLock, incomingConnection, outgoingConnection, updatesPerSecond, mainSocket, signalSocket, sigSockAddr, socketManagerThread, readable, writable, \
    recvData, settings, settingsFormatString, myIP, myIPtimestamp, myTrackerData, useTUNTAPAutosetup, useBackupBroadcastDectection, \
    loopbackSocket, ethernetBufferSize, read, write, internalManagementIdentifier, myTcpUdpMode, UdpMode, TcpMode, connectingTimeout, mainTaskQueue, \
    adapterReadCreator, socketManagerCreator, loggingQueue, logBufferSize, verbosityLevel, alwaysPrint, trackerList
    
    peerList = []
    connList = [[], []]
    settings = [0, 0, 0, ["", 0]]       #[publicIP, timestamp, tunnelMode (TCP or UDP), Trackerdata[Address, reannounce]]
    mainTaskQueue = queue.Queue()
    loggingQueue = queue.Queue()
    connListLock = threading.Lock()

    #Some settings
    settingsFormatString = "4sI?"   #4 chars (1 byte apiece), unsigned int (4 bytes), boolean (1 byte)
    ethernetBufferSize = 8192
    logBufferSize = 65535           #This should probably be optimized later
    internalManagementIdentifier = "OpenGame"
    connectingTimeout =  10         #Wait x seconds for a connection to complete
    #connectionRetryCount = 0       #Never retry a connection, until the program properly handles timeouts
    verbosityLevel = 1              #Print any statements at or over this verbosity level

    #This is a persistent identifier that we need to track
    connID = b""

    #Some 'constants' to make life easier
    notConnected = 0
    connecting = 1
    connected = 2
    removed = 3
    
    add = 0
    remove = 1
    
    readable = 0
    writable = 1
    
    socketManagerCreator = 0
    adapterReadCreator = 1
    
    read = 0
    write = 1
    
    UdpMode = 0
    TcpMode = 1
    
    alwaysPrint = verbosityLevel
    
    #These are for the settings list
    myIP = 0
    myIPtimestamp = 1
    myTcpUdpMode = 2
    myTrackerData = 3
    
    #Should the TUNTAP module set itself up?
    useTUNTAPAutosetup = True
    
    #This uses an alternate method for detecting broadcasts (on WIN 7/8) if the TAP device isn't picking them up
    #If the device is picking them up, it shouldn't be used or every broadcast will be dealt with twice
    #NOTE: this has been broken anyway in the socket manager. Will need to fix if functionality desired.
    useBackupBroadcastDectection = False
    loopbackSocket = 0
    
    incomingConnection = True
    outgoingConnection = False
    
    staleIPtimeout = 21600      #6 hours

    #Set the updates per second value
    updatesPerSecond = 100
    
    #dest = ("tracker.coppersurfer.tk", 6969)
    dest = ("tracker.leechers-paradise.org", 6969)
    #dest = ("exodus.desync.com", 6969)
    #dest = ("9.rarbg.me", 2710)
    #dest = ("tracker.glotorrents.com", 6969)
    
    trackerList = [("tracker.coppersurfer.tk", 6969), ("tracker.leechers-paradise.org", 6969), \
            ("exodus.desync.com", 6969),  ("9.rarbg.me", 2710), ("tracker.glotorrents.com", 6969), ('tracker.blackunicorn.xyz', 6969)]
    
    
    #Create TCP server socket
    #Used to facilitate connection with peers
    tcpPort = 5000
    mainSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mainSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mainSocket.bind(("", tcpPort))
    
    mainSocket.listen(5)
    
    #Append the main socket to the readable subset of the connection list
    connList[readable].append(mainSocket)
    
    
    #Create the socket manager signalling socket
    #Most openGame comms are via queues, but the socket manager waits with select(), so a socket is necessary
    sigSockAddr = ("127.0.0.1", random.randint(49152, 65535))
    socketManagerThread = -1
    signalSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        try:
            signalSocket.bind(sigSockAddr)
        except socket.error:
            sigSockAddr = ("127.0.0.1", random.randint(49152, 65535))
        else:
            break
            

    #Append the main socket to the readable subset of the connection list
    connList[readable].append(signalSocket)
    
    #Create UDP Socket
    #Used for tracker announcing and UDP tunnel mode
    udpPort = 5000
    dataSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        try:
            dataSocket.bind(("", udpPort))
        except socket.error:
            udpPort += 1
        else:
            break
    
    #Append the data socket to the readable subset of the connection list if mode is UDP
    if settings[myTcpUdpMode] == UdpMode: connList[readable].append(dataSocket)


    #Load the settings file, if it exists
    #------------------------
    try:
        #Nothing will happen, and we will just write to the new file on exit
        open('openGame settings', 'x')
        log('Created new settings file.')     #Will never be printed if the file exists
    except FileExistsError:
        try:
            #Load the settings file
            sttngFile = open('openGame settings', 'rb').read()
            
            #Format code: The IP address, and an unsigned int timestamp of when the IP was recorded
            a, settings[myIPtimestamp], c = struct.unpack(settingsFormatString, sttngFile)

            #Update the IP address if the stored one is valid and current
            if settings[myIPtimestamp] > 0 and time.time() - settings[myIPtimestamp] < staleIPtimeout:
                settings[myIP] = socket.inet_ntoa(a)
                log("Public IP restored from saved values: " + str(settings[myIP]), alwaysPrint)
                log("Old IP address is " + str(math.floor(time.time() - settings[myIPtimestamp])) + " seconds old.")
        except:
            log('Failed opening settings file.', alwaysPrint)
            #TODO: delete the bad file, start over.
            #The unpacking failed for some reason, or the file was otherwise invalid. Oh well.
        

    #Determine our public IP address so we recognize ourselves in an IP list
    #TODO: Eventually needs to use STUN servers
    if settings[myIP] == 0:
        log("Either saved IP was stale, invalid, or the settings file was just created. Retrieving public IP...")
        try:
            settings[myIP] = urllib.request.urlopen("http://ipecho.net/plain").read().decode("utf-8")
            settings[myIPtimestamp] = math.floor(time.time())
        except:
            settings[myIP] = input("The online IP service failed to respond, please manually enter your public IP.\n")
            settings[myIPtimestamp] = math.floor(time.time())
        log('Public IP discovered from online service: ' + settings[myIP], alwaysPrint)

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
            log("Failed to locate a TAP device in the windows registry.", alwaysPrint)
            return False
    
    def __init__(self, autoSetup = False):
    
        #These can be used, or not.
        self.myGUID = ""
        self.myInterface = 0
        self.trimEthnHeaders = False
        self.ethernetBufferSize = ethernetBufferSize
        self.myMACaddr = b""
        self.writeDataQueue = queue.Queue()
        self.dataThreads = []
        
        #Set up an overlapped structure for deviceIoControl
        #This originally created an array of overlapped stuctures used throughout this class, but now threads create their own for safety
        self.overlapped = pywintypes.OVERLAPPED()
        self.overlapped.hEvent  = win32event.CreateEvent(None, 0, 0, None)
        
        
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
            
            #Force close if no adapter was found
            if not self.myGUID:
                log("Fatal error: could not locate tap adapter. (Is the adapter properly installed?) \nAutoclosing in 5 seconds.", alwaysPrint)
                time.sleep(5)
                sys.exit()
            
            log("Tap GUID: " + self.myGUID)
            
            self.myInterface = self.createInterface()
            if (self.myInterface):
                #Connect media, and get our MAC address
                self.setMediaConnectionStatus(True)
                self.updateMAC()
            else:
                log("Failed to interface with TAP adapter. Exiting in 5 seconds.", alwaysPrint)
                time.sleep(5)
                sys.exit()
            
            self.dataThreads.append(threading.Thread(target=self.dataListenerThread, args=(mainTaskQueue, ethernetBufferSize), daemon = True))
            self.dataThreads.append(threading.Thread(target=self.dataWriterThread, args=(self.writeDataQueue,), daemon = True))
            self.dataThreads[0].start()
            log('Data listener thread started as daemon.')
            self.dataThreads[1].start()
            log('Data injector thread started as daemon.')
            
    
    #A function to make sure we close our handle and reset media status
    def __del__(self):
        win32file.CloseHandle(self.myInterface)
        self.setMediaConnectionStatus(False)
        log("Handle closed, media disconnected.", "all")
    
    #A function to set the media status as either connected or disconnected in windows
    def setMediaConnectionStatus(self, toConnected):
        #In most TunTap examples, the following line omits an overlapped structure. However, the windows documentation says it should be used
        #if the handle is created with the overlapped flag set. The offsets should be initialized to zero, then left unused.
        win32file.DeviceIoControl(self.myInterface, self.TAP_IOCTL_SET_MEDIA_STATUS, toConnected.to_bytes(4, "little"), None, self.overlapped)
    
    #A simple function to update/return the MAC address
    def updateMAC(self):
        #The following command can not have an overlapped structure passed to it (throws invalid command exception)
        self.myMACaddr = win32file.DeviceIoControl(self.myInterface, self.TAP_IOCTL_GET_MAC, None, 16)
        log("MAC address updated: " + str(self.myMACaddr))
        return self.myMACaddr

    def createInterface(self):
        if self.myGUID == "":
            log("GUID is empty - the device needs to be identified before calling this function.", alwaysPrint)
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
                log("Failed to create interface to TAP device.", alwaysPrint)
                return False
    
    #A function to constantly grab data from the tap device, perform some basic filtering, and enter the results in a queue
    #This function is no longer portable as-is, references to the main queue would need to be removed
    #!This function should not pass any data to the adapter queue if there were any errors!
    def dataListenerThread(self, mainTaskQueue, bufferSize):
        #Create local variable class
        local = threading.local()

        #Allocate our read buffer
        local.readBuffer = win32file.AllocateReadBuffer(bufferSize)
        
        #Create an event to wait on
        local.overlapped = pywintypes.OVERLAPPED()
        local.overlapped.hEvent  = win32event.CreateEvent(None, 0, 0, None)
        #Check to make sure event is working properly - consider manual event
        
        while True:
            try:
                local.readResult = win32file.ReadFile(self.myInterface, local.readBuffer, local.overlapped)
                #This uses GetLastError because the return value will sometimes be false, even though the operation completed
                if win32api.GetLastError() == winerror.ERROR_IO_PENDING:
                    local.a = win32event.WaitForSingleObject(local.overlapped.hEvent, win32event.INFINITE)
                
                    #Diagnostics: if something messed up while waiting
                    if local.a != win32event.WAIT_OBJECT_0:
                        log("Data Listener Thread: Error while waiting on read completion signal: " + str(local.a), alwaysPrint)
                else:
                    log("Read error, return code: " + str(local.readResult[0]) + ", error:" + str(win32api.GetLastError()), alwaysPrint)
                
            except Exception as e:
                log("Device malfunctioned during read operation." + str(e) + " Attempting to continue...", alwaysPrint)
            else:
                #Truncate to the actual data - only for IP Packets
                #TODO: This functionality has been hacked, this needs to be redone to work properly
                if bytes(local.readResult[1][12:14]) == b"\x08\x00" :
                    local.dataLen = int.from_bytes(local.readResult[1][16:18], 'big')
                    mainTaskQueue.put([adapterReadCreator, bytes(local.readResult[1][14*self.trimEthnHeaders:14+local.dataLen])])
                           
                elif bytes(local.readResult[1][12:14]) == b"\x08\x06":
                    local.dataLen = 28       #ARP on IPv4 are always 28 bytes long
                    mainTaskQueue.put([adapterReadCreator, bytes(local.readResult[1][14*self.trimEthnHeaders:14+local.dataLen])])
                    
                # elif bytes(local.readResult[1][12:14]) == b"\x86\xdd":
                    # local.dataLen = int.from_bytes(local.readResult[1][16:20], 'big')
                    # mainTaskQueue.put([adapterReadCreator, bytes(local.readResult[1][14*self.trimEthnHeaders:14+local.dataLen])])
                else:
                    log('Non-IP/ARP packet was discarded. EtherType code: ' + str(bytes(local.readResult[1][12:14])))
    
    def dataWriterThread(self, toWriteQueue):
        #Create local variable class
        local = threading.local()
        
        #Create an event to wait on
        local.overlapped = pywintypes.OVERLAPPED()
        local.overlapped.hEvent  = win32event.CreateEvent(None, 0, 0, None)
    
    
        #Block and wait for data
        #Although this isn't the most concise way to write this, it keeps the ops in loop to a minimum
        if self.trimEthnHeaders:
            #Add Ethernet header back onto the packet (since it was removed)
            #TODO: this function needs to perform a lookup of the MAC address
            local.remoteMACaddr = b"\xc4\x15\x53\xb3\x04\x33"
            
            #All of the below is broken and shouldn't be used.
            while True:
                local.writeData = self.myMACaddr + local.remoteMACaddr + b"\x08\x00" + toWriteQueue.get(block=True)
                win32file.WriteFile(self.myInterface, local.writeData, local.overlapped)
                win32event.WaitForSingleObject(local.overlapped.hEvent, win32event.INFINITE)
        else:
            while True:
                try:
                    local.writeData = toWriteQueue.get(block=True)
                    win32file.WriteFile(self.myInterface, local.writeData, local.overlapped)
                    win32event.WaitForSingleObject(local.overlapped.hEvent, win32event.INFINITE)
                except Exception as e:
                    log("Device malfunctioned during write operation." + str(e) + " Attempting to continue...", alwaysPrint)

    
    #This function updates the IP address and mask of the adapter, and additionally
    #checks to make sure the interface metric is set to 20
    def setDeviceProperties(self, myIP, myMask):
        if not self.myMACaddr:
            log("Mac address not known, cannot set device yet", alwaysPrint)
            return False
        else:
            a= wmi.WMI()
            for interface in a.Win32_NetworkAdapterConfiguration(IPEnabled=1):
                b = binascii.unhexlify(interface.MACAddress.replace(':', ''))
                if b == self.myMACaddr:
                    c = interface.EnableStatic(IPAddress=[myIP],SubnetMask=[myMask])
                    
                    #Check if address was successfully set
                    if c[0] == 0:
                        log("IP Address of interface successfully set:" + str(myIP), alwaysPrint)
                        
                        #Update the connection metric if it isn't 20 and setting address was successful
                        if interface.IPConnectionMetric != 20:
                            oldMetric = interface.IPConnectionMetric
                            #e = interface.SetIPConnectionMetric(1)
                            
                            #The WMI interface will fail to set the metric, but will return successful.  Looking further, it seems to be a windows bug.
                            #Here we simply modify the registry directly.
                            self.ipKey = r"SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\ "[:-1]+self.myGUID
                            try:
                                with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, self.ipKey, access = reg.KEY_ALL_ACCESS) as tcpipInterface:
                                    reg.SetValueEx(tcpipInterface, "InterfaceMetric", 0, reg.REG_DWORD, 20)
                                    reg.SetValueEx(tcpipInterface, "TCPNoDelay", 0, reg.REG_DWORD, 1)
                                    reg.SetValueEx(tcpipInterface, "TCPAckFrequency", 0, reg.REG_DWORD, 1)
                                
                                    log("Interface metric was updated. Old metric was " + str(oldMetric) + ".", alwaysPrint)
                            except Exception as e:
                                log("Failed while attempting to update interface metric: " + str(e), alwaysPrint)
                        return True
                    elif c[0] < 0: 
                        log("IP Address of interface was not successfully set: Administrator privileges are required to configure the interface.", alwaysPrint)
                        return False
                    else:
                        log("IP Address of interface was not successfully set: The operation failed with error number: " + str(c[0]), alwaysPrint)
                        return False
            else:
                log("IP Address of interface was not successfully set: could not find interface.", alwaysPrint)
                return False
        
    
#This function sets up a backup method for receiving broadcasts on win 7 and 8
#Essentially, binds a raw socket to the loopback interface, and for some magical reason, broadcasts appear
#Reference: https://github.com/dechamps/WinIPBroadcast/blob/master/WinIPBroadcast.c
def initBroadcastLoopbackMethod():
    loopbackSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    loopbackSocket.bind(('127.0.0.1', 1))
    
    #Add to the connection list
    connList[readable].append(loopbackSocket)

#This function will output to the log queue for the logging thread to process. Use alwaysPrint to guarantee printing.
def log(message, verbosityLevel = 0):   
    loggingQueue.put((message, verbosityLevel, time.clock()))

#This function logs messages in order of execution, and saves to disk. Additionally, it may print these messages to console
def loggingHandlerThread(loggingQueue, loggingFilename):
    #Create local variable class
    local = threading.local()
    
    with open(loggingFilename, 'w') as local.f:
        log("Logging thread started.")
        while True:
            local.a = loggingQueue.get()
            local.f.write("(" + str(round(local.a[2], 6)) + ")" + str(local.a[0])+"\n")
            local.f.flush()
            
            #Print the statement if it is above the verbosity level, or if there is a supplied message intended for printing
            try:
                int(local.a[1])
                if local.a[1] >= verbosityLevel:
                    print(local.a[0])
            except ValueError:
                print(local.a[1])

#This function properly shuts down the program
def shutdown(*args):
    #Write all settings to file
    #---------------------------
    with open('openGame settings', 'wb') as sttngFile:
        sttngFile.write(struct.pack(settingsFormatString, socket.inet_aton(settings[myIP]), settings[myIPtimestamp], settings[myTcpUdpMode]))
        sttngFile.flush()
        os.fsync(sttngFile.fileno())

    #Close all open sockets (skipping the server socket)
    #---------------------------------------------------
    for sock in connList[readable][1:] + connList[writable]:
        if sock != dataSocket and sock != signalSocket:
            try:
                sock.shutdown(socket.SHUT_RDWR)
                sock.close()
            except socket.error:
                pass
        
    log('Shutdown complete. Exiting...', alwaysPrint)

#This function completely handles making connection to a tracker
def trackerConnect(destAddress):
    global connID   #This fixes a strange bug that creeped in somewhere. TODO: Investigate further.
    transID = random.randrange(65535).to_bytes(4, 'big')
    data = 0x41727101980.to_bytes(8, 'big') + 0x0.to_bytes(4, 'big') + transID

    log(data, "Connecting to tracker " + str(destAddress[0]) + " on port " + str(destAddress[1]) + ".")
    dataSocket.sendto(data, destAddress)

    #Decode response
    #------------------------
    #TODO: make this select based, and give user option to wait or move on if response is slow
    recvData, addr = dataSocket.recvfrom(ethernetBufferSize)

    #Perform integrity checks and
    #Return True if response checks out
    if len(recvData) > 15:
        if transID == recvData[4:8]:
            if 0x0.to_bytes(4, 'big') == recvData[:4]:
                #The response is valid
                log("Response: " + str(recvData), "Connection to tracker completed.")   
                connID = recvData[8:16]
                log("Connection ID: " + str(connID))
                return True
            else:
                log("Received action is incorrect in the tracker's response.", alwaysPrint)
        else:
            log("Received Transaction ID is incorrect in the tracker's response.", alwaysPrint)
            log("Wanted: " + transID + " Received: " + recvData[4:8], alwaysPrint)
    else:
        log("Response too short", alwaysPrint)

    #If we didn't return earlier, the response is bad
    return False

#A function to announce to trackers
def Announce():
    #Prepare payload
    a = 0x1.to_bytes(4, 'big') #action
    transID = random.randrange(65535).to_bytes(4, 'big') #TransID
    iH = 'opnGameGroundControl'.encode('ascii')
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
    #log(payload)
    
    dataSocket.sendto(payload, dest)
    log("Announced to tracker.", alwaysPrint)

#A function to decode addresses returned from trackers into the peerlist
#Used to initialize an empty peerlist
def decodePeerAddresses(rawAddr):
    #Peerlist structure by first indice is as follows:
    #0: address of peer
    #1: port of peer [TCP port, UDP port if known (defaults to None)]
    #2: status of peer
    #3: context sensitive storage of peer management data. Depends on status.
    
    local = threading.local()
    
    local.decodedAddresses = []
    
    #Sanity check
    if len(rawAddr) % 6 != 0: log("Error while decoding addresses: raw address string is not devisible by 6.", alwaysPrint)
    
    for i in range(0, len(rawAddr), 6):
        a = socket.inet_ntoa(rawAddr[i:i+4])
        p = int.from_bytes(rawAddr[i+4:i+6], 'big')
        
        #Don't add an address to the list if it is ours
        if a != settings[myIP]:
            local.decodedAddresses.append((a, p))
            
            #peerList.append([a, [p, None], notConnected, [0, None]])
    return local.decodedAddresses

#A function to set the status of a peer in the list. Potentially unthreadsafe.
#Will add an address into the peerlist if it doesn't already exist.
def setPeerStatus(addr, status, peerSock = None):
    #Brief search to see if the peer is currently in our list, adding it if not
    pos = 0     #We initiate pos here to handle the case where the peerlist is empty
    for pos, (a, b, c, d) in enumerate(peerList):
        if (a, b[0]) == addr:
            log("Peer " + str(addr) + " already exists in the peer list.")
            break
    else:
        if status != removed:
            #Add peer into the peerlist, tracking both the address and socket
            if peerSock == None: log("WARNING: New peer added to list without an associated socket!")
            peerList.append([addr[0], [addr[1], None], status, [peerSock, None]])
            log('Added to peerlist.')
            log(peerSock)
        else:
            log('The peer was not found in the peerlist to remove.')

        
    #Edit the peer's status
    if status == removed:
        peerList.pop(pos)           #Remove the position from the list
        routing.updateMyAddr()      #Check addresses after a peer removal
        
    else:
        if status == notConnected:
            a = [-1,] #Would normally be setting a new timeout
            
        elif status == connecting:
            #We store the peer's socket in the storage along with a placeholder for an internal IP address, and the time we began connecting
            a = [peerSock, None, math.floor(time.time())]

        else:
            a = peerList[pos][3]    #Preserves the existing storage
            
            #If we know our IP, tell them
            routing.announceMyInternalInfo(peerList[pos][3][0])
        
        #This may be incorrect    
        peerList[pos] = [peerList[pos][0], peerList[pos][1], status, a]
        
    
    #Print diagnostic text
    if status == notConnected:
        log("Peer at " + str(addr) + " set to not connected.")
    elif status == connecting:
        log("Peer at " + str(addr) + " set to connecting.")
    elif status == connected:
        log("Peer at " + str(addr) + " set to connected.")
    elif status == removed:
        log("Peer at " + str(addr) + " was removed from the peer list.")

#A potentially pointless function to connect to peers
#Incoming connections always called from socketManager thread, Outgoing always called from runManager Thread
def peerConnection(incom, address = ""):
    if incom:
        #Handle the new incoming connection
        peerSock, peerAddr = mainSocket.accept()
        log('Accepted a connection from ' + str(peerAddr), alwaysPrint)
        setPeerStatus(peerAddr, connected, peerSock)

        #Add to the connection list
        modifyConnList(peerSock, readable, add)

        #Debug data
        log("New connection list: " + str(connList))
    else:
        #Create a new outgoing connection
        #Until STUN servers can be implemented
        peerSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        peerSock.setblocking(False)
        log('Attempting a connection to ' + str(address), alwaysPrint)
        #The connect will give an error since it cannot instantly complete
        #Add it to the writables list to tell when the connect finishes
        try:
            peerSock.connect(address)
        except OSError:
            pass
        modifyConnList(peerSock, writable, add)
        setPeerStatus(address, connecting, peerSock)

#A function to manage modifications to the connection list through threads
def modifyConnList(socket, subList, addRemove):
    #The following needs to be atomic to prevent corruption in certain cases
    connListLock.acquire()
    if addRemove:
        connList[subList].remove(socket)
    else:
        connList[subList].append(socket)
    connListLock.release()
        
    #If the thread calling this function isn't the socket manager, we need to notify the socket manager
    if threading.current_thread() != socketManagerThread:
        signalSocket.sendto(b"a", sigSockAddr)
        log("Notified socket manager of external changes made by thread" + str(threading.current_thread()) + ".")
    else:
        log('Socket manager has modified the connection list.')

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
        self.prefix = "10.0.0."
        self.netMask = "0111"           #This is used piecemeal; refers to which fields need to be checked as broadcast (for internal use only)
        self.myAddr = len(peerList)+1     #This is an initial heuristic that may be overridden when our address is finalized
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
        log('Routing tools initialized. My internal ip address initialized to :' + self.prefix + str(self.myAddr), alwaysPrint)
        self.updateMyAddr()
        
    #Function to determine whether or not an address is broadcast
    def isBroadcast(self, addr):
        for i in range(4):
            if int(self.netMask[i]) == True and int(addr[i]) != 255:
                return False        #The address is not a broadcast
        else:
            return True
    
    #Function to add a newly discovered address from a peer
    def addDiscoveredInfo(self, peerSockFileDisc, intrnlData):
        decodedPort = int.from_bytes(intrnlData[1:3], 'big')
        #Yet another shallow copy of peerList, so we can modify peerList without messing up the loop
        for i, a in enumerate(peerList[:]):
            if a[3][0].fileno() == peerSockFileDisc:
                if peerList[i][3][1] != None:
                    log('The peers internal IP has already been set. Re-setting...')
                peerList[i][3][1] = intrnlData[0]
                peerList[i][1][1] = decodedPort
                log('Internal management info received. Peer at ' + str(a[3][0].getpeername()) + " has internal IP :" + self.prefix + str(intrnlData[0]) + " and UDP port:" + str(decodedPort), alwaysPrint)
                self.updateMyAddr()
                break
            else:
                log("ERROR: peer not found when trying to update data!")

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
                if a[2] == connected or a[2] == connecting:
                    if a[3][1] == None:
                        log("Not able to set internal IP yet.")
                        return False
                    else:
                        self.addrInUse[a[3][1]] = True
                
            else:
                #Set our address to the first un-used address
                self.myAddr = self.addrInUse.index(False)
                self.isAddrSet = True
                
                #Update the adapter to match
                myTap.setDeviceProperties(self.prefix + str(self.myAddr), self.myMask)
                
                log("Internal IP has now been set to: " + self.prefix + str(self.myAddr), alwaysPrint)
                
                #Propogate the address to all peers
                self.announceMyInternalInfo('_global')
                
                return True
        else:
            log('Address has already been set.')
            return True
    
    #This function will tell a peer our IP address, when we know it
    def announceMyInternalInfo(self, peerSock):
        self.payload = bytes(chr(self.myAddr), "utf-8") + udpPort.to_bytes(2, "big")
        if peerSock != '_global':
            if self.isAddrSet:
                log("Announced internal management data (" + self.prefix + str(self.myAddr) + ") to " + str(peerSock.getpeername()), alwaysPrint)
                peerSock.sendall(bytes(internalManagementIdentifier, "utf-8") + self.payload)
            else:
                log("Announced tentative internal management data (" + self.prefix + str(self.myAddr) + ") to " + str(peerSock.getpeername()), alwaysPrint)
                peerSock.sendall(bytes(internalManagementIdentifier, "utf-8") + self.payload)
        else:
            log("Propagating IP address...", alwaysPrint)
            for (a1, a2, status, storage) in peerList:
                if status == connected:
                    log("Announced internal management data (" + self.prefix + str(self.myAddr) + ") to " + str(storage[0].getpeername()))
                    storage[0].sendall(bytes(internalManagementIdentifier, "utf-8") + self.payload)
    
    def routeAndSend(self, dataToSend):
        #Calculate IPv4 address here to avoid repeated calculation inside the loop
        destAddress = dataToSend[(not myTap.trimEthnHeaders)*14+16:(not myTap.trimEthnHeaders)*14+20]
        
        #Detect ARP packets and handle accordingly
        if not myTap.trimEthnHeaders and dataToSend[12:14] == b"\x08\x06":
            isArp = True
        else:
            isArp = False
        
        #This may need to be locked, but we don't here for speed
        for addr, port, status, extra in peerList[:]:
            if status == connected:
                #Check first to see if the packet is a broadcast packet
                #The position we read from changes depending on whether ethernet headers are stripped, so make sure
                #setting is correct in the TUNTAP class
                if self.isBroadcast(destAddress) or isArp:
                    if settings[myTcpUdpMode] == TcpMode:
                        extra[0].sendall(dataToSend)
                        log("Broadcast data sent to : " + str(extra[0].getpeername()))
                    else:
                        if port[1]:
                            dataSocket.sendto(dataToSend, (addr, port[1]))      #Send to their advertised port
                            log("UDP broadcast data sent to: (" + str(addr) + ", " + str(port[1]) + ")")
                        else:
                            dataSocket.sendto(dataToSend, (addr, udpPort))      #Use our port if port unknown
                            log("UDP broadcast data sent to: (" + str(addr) + ", " + str(udpPort) + ")")
                else:
                    #Here we send data to a single peer
                    #Search the peerlist for the peer, then send
                    if extra[1] != None:
                        if settings[myTcpUdpMode] == TcpMode:
                                if socket.inet_aton(routing.prefix + str(extra[1])) == destAddress:
                                    extra[0].sendall(dataToSend)
                                    #log("Sent data only to : " + str(extra[0].getpeername()) + ", internal IP: " + str(routing.prefix + extra[1]))
                        else:
                            if socket.inet_aton(routing.prefix + str(extra[1])) == destAddress:
                                if port[1]:
                                    dataSocket.sendto(dataToSend, (addr, port[1]))      #Send to their advertised port
                                    log("Sent UDP data only to : (" + str(addr) + ", " + str(port[1]) + "), internal IP: " + routing.prefix + str(extra[1]))
                                else:
                                    dataSocket.sendto(dataToSend, (addr, udpPort))      #Use our port if port unknown
                                    log("Sent UDP data only to : (" + str(addr) + ", " + str(udpPort) + "[assumed, no port advertised]), internal IP: " + routing.prefix + str(extra[1]))

#This thread waits on all sockets
#The thread will automatically handle new connections, or connections closed by remote peer
#All other data is read and placed on the mainTaskQueue
def socketManager(mainTaskQueue, pauseEvent):
    local = threading.local()
    local.s = None
    
    while True:
        #Block until some socket is ready
        local.rSock, local.wSock, local.e = select.select(connList[readable],connList[writable],[])

        #All of the below has been revised to place file descriptors on the queue, rather than the sockets itself
        #This avoids a strange bug where 1% of the time, placing a socket on the queue will silently fail
        for local.s in local.rSock:
            #Handle new incoming connections
            if local.s == mainSocket:
                #Since this is the only case in which the socket isn't actually handled from the socketManager, we
                #Need to use an event to prevent the socketManager and runManager racing each other
                mainTaskQueue.put([socketManagerCreator, [mainSocket.fileno(),]])
                pauseEvent.clear()
                pauseEvent.wait()

            #Handle broadcasts picked up via the loopback socket
            elif local.s == loopbackSocket:
                pass
            
            #Handle wake-up signals sent over the signal socket
            elif local.s == signalSocket:
                local.s.recvfrom(ethernetBufferSize)
            
            #Handle data from the data socket (but only when in UDP mode)
            elif local.s == dataSocket:
                #log('New socket(s) available to read: dataSocket')
                local.data = local.s.recvfrom(ethernetBufferSize)
                mainTaskQueue.put([socketManagerCreator, [local.s.fileno(), local.data]])    


            else:
                #Receive the data
                #This is in a try block to catch force-closed connection exceptions
                try:
                    local.data = local.s.recv(ethernetBufferSize)
                    if not local.data: raise ConnectionAbortedError
                except ConnectionError: #(ConnectionAbortedError, ConnectionRefusedError, ConnectionResetError):
                    #Connection forcefully closed
                    log('Peer at  ' + str(local.s.getpeername()) + ' has disconnected.', alwaysPrint)
                    modifyConnList(local.s, readable, remove)
                    
                    #Remove the disconnected peer
                    setPeerStatus(local.s.getpeername(), removed)
                    
                    #Close the socket
                    local.s.close()
                else:
                    mainTaskQueue.put([socketManagerCreator, [local.s.fileno(), local.data]])
                

        for local.s in local.wSock:
            log('New connections completed.', 2)
            #Set peers to connected state, move socket to readable list
            modifyConnList(local.s, readable, add)
            modifyConnList(local.s, writable, remove)
            setPeerStatus(local.s.getpeername(), connected)

            
#The main manager loop
def runManager():
    #Calculate the deltatime
    deltaTime = 1/updatesPerSecond
    
    #Start the socket manager as daemon
    socketManagerPauseEvent = threading.event()
    socketManagerThread = threading.Thread(target=socketManager, args=(mainTaskQueue, socketManagerPauseEvent), daemon = True)
    socketManagerThread.start()

    #Inform the user on program exit
    log('Connection manager is now running. \nPress CTRL + C to close this program at any time', alwaysPrint)

    while True:
        #Block and wait for jobs
        try:
            taskCreator, taskInfo = mainTaskQueue.get(block=True, timeout=deltaTime)
        except queue.Empty:
            pass
        else:
            if taskCreator == socketManagerCreator:
                #Handle tasks from the socket manager

                #Handle data from the data socket (but only when in UDP mode)
                if taskInfo[0] == mainSocket.fileno():
                    #The socket manager will wait until this operation completes to prevent a race
                    peerConnection(incomingConnection)
                    socketManagerPauseEvent.set()
                
                elif taskInfo[0] == dataSocket.fileno():
                    if settings[myTcpUdpMode] == TcpMode:
                        #Ignore it, since we are in the wrong mode
                        pass
                    else:
                        #Diagnostics
                        #log('Incoming UDP data from ' + str(taskInfo[1][1]))
                        #log("[DATAIN]"+str(taskInfo[1][0])+"[/DATA]")
                        
                        #Send packets to the TAP adapter write queue
                        myTap.writeDataQueue.put(taskInfo[1][0])

                else:
                    #Recreate the socket (note that, contrary to what the docs say, this DOES NOT return the same socket)
                    sock = socket.socket(fileno=taskInfo[0])
                    #Diagnostics
                    log('Incoming TCP data from ' + str(sock.getpeername()))
                    log(taskInfo)
                    
                    if taskInfo[1][:len(internalManagementIdentifier)] == internalManagementIdentifier.encode():
                        #Send internal management info to be decoded
                        routing.addDiscoveredInfo(taskInfo[0], taskInfo[1][len(internalManagementIdentifier):])
                    else:
                        #Send packets to the TAP adapter write queue
                        #This behavior will be phased out in the future as TCP sockets are used exclusively for control data
                        myTap.writeDataQueue.put(taskInfo[1])
            
            elif taskCreator == adapterReadCreator:
                #Handle data from the adapter
                routing.routeAndSend(taskInfo)
                #log("[DATAOUT]"+str(taskInfo)+"[/DATA]")
            else:
                log("Error: taskCreator doesn't match any known creator")
    
        #Manage peer list
        #---------------------------------
        #Here, we will loop over all peers, updating and connecting, etc
        #We loop over a shallow copy, because we may modify the list inside of this loop
        for i, (a, p, connStatus, connStorage) in enumerate(peerList[:]):
            #Handle all unconnected peers
            #Unconnected peer storage is as follows:
            #0 : Reconnect timeout
            #1 : Total time disconnected

            #Nothing of anything applies to our own IP, so skip
            if connStatus == notConnected:
                t = connStorage[0] #The first stored variable is the timeout
                
                if t < 0:
                    #Reconnect when timeout below zero
                    peerConnection(outgoingConnection, (a, p[0]))

                else:
                    #Decrease the reconnect timer
                    peerList[i] = [a, p, connStatus, [t-deltaTime]]
                    
            elif connStatus == connecting:
                if time.time() - connStorage[2] > connectingTimeout:
                    #Connection timed out
                    log('Attempted connection to ' +str(connStorage[0].getpeername()) +  ' has timed out. Peer removed from list.', alwaysPrint)
                    modifyConnList(connStorage[0], writable, remove)
                    
                    #Remove the disconnected peer
                    setPeerStatus(connStorage[0].getpeername(), removed)
                    
                    #Close the socket
                    connStorage[0].close()
    

#--Main program sequence--
#-------------------------
time.clock()    #Starts our internal clock, used for logging

#Check for duplicate program instances
try:
    win32ui.FindWindow(None, "openGame")
except win32ui.error:
    #We set our window down here so we don't find our own window earlier
    ctypes.windll.kernel32.SetConsoleTitleW("openGame")
else:
    print("Duplicate program instance found. Please close the other running instance before restarting. Autoclosing in 5 seconds.")
    time.sleep(5)
    os._exit(0)

Initialize()
try:
    logThread = threading.Thread(target=loggingHandlerThread, args=(loggingQueue, os.path.dirname(os.path.abspath(__file__))+r'\log.txt'), daemon = False)
except NameError:
    #When running as executable, the __file__ global is not defined.
    logThread = threading.Thread(target=loggingHandlerThread, args=(loggingQueue, os.path.dirname(os.path.abspath(sys.argv[0]))+r'\log.txt'), daemon = False)
logThread.start()
log("Initialized. Verbosity level is set to " + str(verbosityLevel))

#Setup shutdown handlers so program gracefully closes
#----------------------------------------------------
#We use this to catch the console exiting, since it fires on the most events (user closing openGame, log-off, restart, etc)
win32api.SetConsoleCtrlHandler(shutdown, True)


#Instantiate our tuntap class and have it auto-setup
myTap = tuntapWin(useTUNTAPAutosetup)
log("Tuntap device initialized, interface created.", alwaysPrint)


#Connect to our tracker of choice, and announce if it succeeds
if trackerConnect(dest):
    #Store connection ID and announce
    Announce()
else:
    log('Connection to tracker failed. Autoclosing in 5 seconds', alwaysPrint)
    time.sleep(5)
    sys.exit()

#Decode announce response
#------------------------
recvData, addr = dataSocket.recvfrom(ethernetBufferSize)
log("Announce response: " + str(recvData))
if len(recvData) > 19:
    #TODO: check action, etc, blahblah
    log("Reannounce interval: " + str(int.from_bytes(recvData[8:12], 'big')) + " seconds")
    for addr in decodePeerAddresses(recvData[20:]):
        setPeerStatus(addr, notConnected)
    
    #Diagnostics
    log("Peerlist: \n"+str(peerList), alwaysPrint)
else:
    log("Announce response is too short", alwaysPrint)
routing = routingTools()

#Enter the main management loop
#------------------------------

try:
    runManager()
#So that no traceback is printed for a CTRL+C
except KeyboardInterrupt:
    shutdown()
    os._exit()
finally:
   shutdown()