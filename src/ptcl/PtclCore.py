'''
Created on Mar 2, 2016

@authors: 
Harsh Chaturvedi
Information Security Institute
Johns Hopkins University

Xiao Chong(Cyrus) Chua
Information Security Institute
Johns Hopkins University

Under the Guidance of : 

Dr Seth Neilson
Johns Hopkins University
'''

import random

import hashlib

import logging

logger = logging.getLogger(__name__)

from playground import playgroundlog

from playground.network.message.StandardMessageSpecifiers import *

from playground.network.common import PlaygroundAddress, Packet

from playground.network.common import SimpleMessageHandlingProtocol, StackingProtocolMixin

# MessageDefinition is the base class of all automatically serializable messages
from playground.network.message.ProtoBuilder import MessageDefinition

from playground.network.client.ClientApplicationTransport import StackingTransportMixin

# MessageData has a static method used for constructing a serializable class
from playground.network.message import MessageData

# ClientBase is the way we connect into Playground
from playground.network.client import ClientBase

from playground.network.common import Timer

from playground.network.client.ClientApplicationServer import ClientApplicationServer

from twisted.internet.task import LoopingCall

#Extension(...,define_macros=[('S',1),('SA',2),('A',3),('D',4),('F',5),('FA',6),('NC',7)])
#Extension(...,define_macros=[('SANITY_ERROR',0),('ERROR',0),('TIMEOUT',0),('SUCCESS',1)])

DATALISTSIZE = 20
WINDOWSIZE = 16
RCVWINDOW = 16

class PTCLMessage(MessageDefinition):
	PLAYGROUND_IDENTIFIER = "PTCLMessageID"
	MESSAGE_VERSION = "1.0"
	BODY = [
		 ("Hash", STRING),
		 ("MessageType", STRING),
		 ("MessageSeq", UINT8),
		 ("AckSeq", UINT8),
		 ("Data", STRING)
	]
	
class PTCLProtocol(SimpleMessageHandlingProtocol, StackingProtocolMixin, StackingTransportMixin):
    def __init__(self,factory,addr):
        self.__state = 0    # current state of the connection
        self.__retries = 0  # retries of packet sending 
        self.__ack_retries = 0 # retransmission of ACK 
        self.__currSeq = 0  # the last packet sent
        self.__curr_ackSeq = 0 # the last acknowledged packet 
        self.__sanity = -1  # hash match or not
        self.__waiting = 0   # Waiting for ACK
        self.__messageFromTop = "" # Message sent by the top layer 
        self.__window = []  # Window of unacknowledged packets
        self.__rcvWindow = [(-1,'')]*RCVWINDOW # Window of received packets 
        self.__dataList = [] # Data buffer
        self.__connected = 0  # Three way Handshake is complete or not started
        self.__handshake = 0 # Three way handshake started but not complete
        self.__finhandshake = 0 # if set FINACK sequence started but not complete
        self.__dataPoint = 0 # The extent to which the dataList is full
        self.__winPoint = -1 # The extent to which the window is full
        self.__last_contig = 0 # The sequence of the last contiguously received packet
        self.__next_expected = -1
        self.__timely= None
        self.__hb_timer = None # This timer is for starting Heart Beat ACKs once all data has been sent
        self.__exp_backoff = 10
        self.__session_timer = None
        self.__fin_timer = None
        SimpleMessageHandlingProtocol.__init__(self, factory,addr)
        self.registerMessageHandler(PTCLMessage,self.__ptclMessageHandler)

    def __ptclMessageHandler(self, protocol, msg):
        ##print "I have received a message from the network, checking it's sanity:"
        msgObj = msg.data()
        # first compare the hashes.
        sane = self.sanity(msg)
        if sane:
            ##print "packet is sane"
            pass
        else:
            ##print "packet is insane"
            return 0
     
        # Bifurcate the code flow based on the message type 
        # handleConnectionMessages takes care of SYN/SYNACK/ACK/FIN/FINACK
        # handleDataAck handles the ACKs sent to acknowledge successful data delivery
        # handleDataRcvMessage handles the data messages
        if msgObj.MessageType == "SYN":
            #DO This
            ##print "I got a SYN \n"
            self.__handleConnectionMessages(1,msgObj)
            # TO DO check for current state.

        elif msgObj.MessageType == "SYNACK":
            #Do this
            ##print "I got a SYNACK \n"
            self.__handleConnectionMessages(2,msgObj)

        elif msgObj.MessageType == "ACK":
            #DO This
            ##print "I got an ACK \n"
            if(self.__connected):
                ##print "For connected connection"
                self.__handleAck(msgObj)
            else:
                ##print "For unconnected connection"
                self.__handleConnectionMessages(3,msgObj)

        elif msgObj.MessageType == "DATA":
            #Fixed : would allow a DATA packet to be processed directly without a connection
            ##print "I got DATA \n"
            self.__data_timer = Timer.OneshotTimer(lambda:self.checkData())
            if(self.__connected ==1):
                self.__handleDataRcvMessage(msgObj)
            else:
                pass
                ##print "No connection present aborting"

        elif msgObj.MessageType == "FIN":
            #Do This
            ##print "I got a FIN \n"
            self.__handleConnectionMessages(6,msgObj)

        elif msgObj.MessageType == "FINACK":
            #Do this
            ##print "I got a FINACK"
            self.__handleConnectionMessages(8,msgObj)

        else:
            #TODO - Do nothing - log it - ##print something to screee/log
            return 0

    def checkSession(self):
       #print "I have been waiting for 35 seconds. this shit is not worth it.. I am leaving.."
       Timer.callLater(0.1,lambda:self.getHigherProtocol().connectionLost("Connection Lost Due to Inactivity"))
  
    def checkData(self):
       ###print "Inside checkData that means I did not get a new Data Message"
       ###print "Re sending ack for last contiguous packet"
       if (self.__finhandshake == 1):
            ##print "Connection Ending no need to send handshake"
            return None
       self.__exp_backoff *= 2
       if self.__exp_backoff >= 10:
           self.__exp_backoff = 10
       self.__handleConnectionMessages(7) 
       self.__hb_timer = Timer.OneshotTimer(lambda:self.checkData())
       self.__hb_timer.run(self.__exp_backoff)

    def checkState(self,curr,msgObj=None):
        ###print "Inside CheckSTate for state: ",curr
        if self.__connected == 0:
            ##print "There is no existing connection"
            return 
        if (self.__state == curr or self.__state > 8):
            ##print "Timer expired for state ",self.__state," and count is ",self.__retries
            self.__retries += 1
            # After timeout the receiver tries to send a SYNACK max
            # three times. After that it just throws an error
            if(self.__retries > 10):
                ##print("Haven't received a response, It seems the connection is broken")
                self.__state =9  #"TIMEOUT"
                self.__retries = 0
                return 
            #The sender resends the SYNACK packet
            if (msgObj != None):
                self.__handleConnectionMessages(curr,msgObj)
            else: 
                self.__handleConnectionMessages(curr)
        elif (self.__state > curr):
            ##print "The state changed, we are good, Not timing out and resetting number of retries"
            self.__retries = 0
        else:
            pass
            # TODO Code should never reach here.``
            ##print("Do nothing the code flow should never hit this ")

    def hash_it(self, pkt):
        msg = hashlib.sha256()
        msg.update(pkt.serialize())
        hashed = msg.hexdigest()
        return hashed

    def sanity(self, msg):
        msgObj = msg.data()
        origHash = msgObj.Hash
        msg["Hash"].setData('0') 
        unhashed = hashlib.sha256()
        unhashed.update(msg.serialize())
        hashed = unhashed.hexdigest()
        if (hashed == origHash):
            return True
        else: 
            return False

    def connectionMade(self):
        ###print "This is the higher protocol: ", self.getHigherProtocol(), "This is us:", self
        ###print "This is our transport: ",self.transport 
        self.getHigherProtocol().makeConnection(self)

    def __handleConnectionMessages(self,state,msgObj=None):
        if state == 0:
            self.__state = 0
            self.__connected =0
            self.__handshake =1
            self.__currSeq = random.getrandbits(32)
            ##print "Preparing to send a SYN Message"
            ##print "The sequence number I am sending is :", self.__currSeq
            responseMessageBuilder = MessageData.GetMessageBuilder(PTCLMessage)
            responseMessageBuilder["Hash"].setData('0')
            responseMessageBuilder["MessageType"].setData("SYN")
            responseMessageBuilder["MessageSeq"].setData(self.__currSeq)
            responseMessageBuilder["AckSeq"].setData(0)
            responseMessageBuilder["Data"].setData("")
            # TODO Calculate the hash of the whole packet created above
            # and fill it in the HASH field of the packet
            msg_hash = self.hash_it(responseMessageBuilder)
            responseMessageBuilder["Hash"].setData(msg_hash)
            self.__waiting =1
            self.transport.writeMessage(responseMessageBuilder)
            Timer.callLater(0.1, lambda:self.checkState(0))

        elif state == 1:
            # Server state where server received a SYN packet and will now send an SYNACK
            if (self.__state ==3 or self.__state == 2):
                ##print "Already Connected"
                return 
            ##print "I have got a SYN and will now Send a SYNACK"
            self.__state = 1
            self.__currSeq = random.getrandbits(32)
            #self.__curr_ackSeq = msgObj.MessageSeq
            ##print "The sequence number I got in the SYN is : ",msgObj.MessageSeq,"and the sequence number I am sending in the SYNACK is: ", self.__currSeq
            if(msgObj != None):
                self.__curr_ackSeq = msgObj.MessageSeq

                logger.debug("Harsh: %s Hey! We got our SYN, setting curr_ackSeq to %d" %(self._addr,self.__curr_ackSeq))
                #Prepare and send a SYNACK Message
                responseMessageBuilder = MessageData.GetMessageBuilder(PTCLMessage)
                responseMessageBuilder["Hash"].setData('0')
                responseMessageBuilder["MessageType"].setData("SYNACK")
                responseMessageBuilder["MessageSeq"].setData(self.__currSeq)
                responseMessageBuilder["AckSeq"].setData(self.__curr_ackSeq)
                responseMessageBuilder["Data"].setData("")
                msg_hash = self.hash_it(responseMessageBuilder)
                responseMessageBuilder["Hash"].setData(msg_hash)
                self.transport.writeMessage(responseMessageBuilder)
                Timer.callLater(0.1,lambda:self.checkState(1))
        elif state == 2:
            if (self.__state >= 2):
                ##print "Multiple SYNACK, Discard"
                return
            self.__state = 2
            ##print "I have got a SYNACK and will now send an ACK followed by data"
            ##print "The sequence number I got is : ",msgObj.MessageSeq, "and the sequence number i am sending is : ", self.__currSeq
            # Extract sequence number and set state variable
            self.__curr_ackSeq = msgObj.MessageSeq
            logger.debug("Harsh: %s Hey! We got our SYNACK, setting curr_ackSeq to %d" %(self._addr,self.__curr_ackSeq))
            #Prepare and send an ACK Message
            responseMessageBuilder = MessageData.GetMessageBuilder(PTCLMessage)
            responseMessageBuilder["Hash"].setData('0')
            responseMessageBuilder["MessageType"].setData("ACK")
            responseMessageBuilder["MessageSeq"].setData(0)
            responseMessageBuilder["AckSeq"].setData(msgObj.MessageSeq)
            responseMessageBuilder["Data"].setData("")
            #TODO Calculate the hash of the whole packet created above
            # and fill it in the HASH field of the packet
            msg_hash = self.hash_it(responseMessageBuilder)
            responseMessageBuilder["Hash"].setData(msg_hash)
            self.transport.writeMessage(responseMessageBuilder)
            ##print "sent an ACK , we are connected ,now sending Data:"
            ##print "Setting connected in client"
            self.__handshake =1
            self.__connected =1
            

            #self.__last_contig = self.__curr_ackSeq
            #set the timer
            #No timer because now data has to be sent, after sending ACK you don't 
            # wait and start pushing data directly
            ##print "Sent Data"
            #print "Setting hb timer on receiver"
            self.__hb_timer = Timer.OneshotTimer(lambda:self.checkData())
            self.__hb_timer.run(10)
            Timer.callLater(0.1,lambda:self.processQueue()) 
            self.__session_timer = Timer.OneshotTimer(lambda:self.checkSession())
            self.__session_timer.run(35)
            #Timer.callLater(0.1,lambda:self.checkState(2,msgObj))
            #Check if the state has looped back to the same state. Store the current time
            # and check if it has changed after timeout
        elif state == 3:
            # Server side state, once server has received ACK from Client in response to SYNACK
            self.__state = 3
            # Extract sequence number, check and set state variable
            ##print "I have got an ACK"

            #self.__currSeq = self.__currSeq +1
            ##print "Setting connected in server"
            self.__connected = 1
            self.__handshake = 1
            self.__last_contig = msgObj.MessageSeq
            ##print "The sequence number I got is: ", msgObj.MessageSeq
            #print "Setting hb timer on sender"
            self.__hb_timer = Timer.OneshotTimer(lambda:self.checkData())
            self.__hb_timer.run(10)
            self.__session_timer = Timer.OneshotTimer(lambda:self.checkSession())
            self.__session_timer.run(35)
            
        elif state == 5:
            self.__state = 5
            # Extract sequence number and set state variable
            ##print "I am going to send a FIN Message"
            self.__currSeq = self.__currSeq +1
            #Prepare and send an FIN Message
            responseMessageBuilder = MessageData.GetMessageBuilder(PTCLMessage)
            responseMessageBuilder["Hash"].setData('0')
            responseMessageBuilder["MessageType"].setData("FIN")
            responseMessageBuilder["MessageSeq"].setData(self.__currSeq)
            responseMessageBuilder["AckSeq"].setData(0)
            responseMessageBuilder["Data"].setData("")
            #TODO Calculate the hash of the whole packet created above
            # and fill it in the HASH field of the packet
            msg_hash = self.hash_it(responseMessageBuilder)
            responseMessageBuilder["Hash"].setData(msg_hash)
            self.transport.writeMessage(responseMessageBuilder)
            #set the timer
            self.__timely = Timer.callLater(0.1,lambda:self.checkState(5))
        elif state == 6:
            ##print "I got a FIN Message and I will send a FINACK"
            self.__finhandshake = 1
            self.__state = 6
            self.__curr_ackSeq = msgObj.MessageSeq
            #Prepare and send an FINACK Message
            responseMessageBuilder = MessageData.GetMessageBuilder(PTCLMessage)
            responseMessageBuilder["Hash"].setData('0')
            responseMessageBuilder["MessageType"].setData("FINACK")
            responseMessageBuilder["MessageSeq"].setData(0)
            responseMessageBuilder["AckSeq"].setData(self.__curr_ackSeq) 
            responseMessageBuilder["Data"].setData("")
            #TODO Calculate the hash of the whole packet created above
            # and fill it in the HASH field of the packet
            msg_hash = self.hash_it(responseMessageBuilder)
            responseMessageBuilder["Hash"].setData(msg_hash)
            ##print "Sending FINACK now: "
            self.transport.writeMessage(responseMessageBuilder)
            Timer.callLater(0.1,lambda:self.getHigherProtocol().connectionLost("Received FIN"))
            self.transport.loseConnection()
            self.__connected = 0
        elif state == 7:
            ###print "I am suppose to send an ACK for data received:"
            responseMessageBuilder = MessageData.GetMessageBuilder(PTCLMessage)
            responseMessageBuilder["Hash"].setData('0')
            responseMessageBuilder["MessageType"].setData("ACK")
            responseMessageBuilder["MessageSeq"].setData(0)
            logger.info("Harsh: %s Sending ACK with ACK Sequence %d" %(self._addr,self.__curr_ackSeq))
            responseMessageBuilder["AckSeq"].setData(self.__curr_ackSeq)
            # There is no data being piggy bagged on the ACK , if required put the data here from the 
            # buffer where it is stored. 
            responseMessageBuilder["Data"].setData("")
            responseMessageBuilder["Hash"].setData(self.hash_it(responseMessageBuilder))
            self.transport.writeMessage(responseMessageBuilder)
        elif state == 8:
            self.__state = 8
            self.__currSeq = 0
            self.__curr_ackSeq = 0
            ##print "I received a FINACK - Trying to terminate connection"
            ##print "dataList and rcvWindow are both empty, safe to terminate, connectionLost() called"
            Timer.callLater(0.2,lambda:self.getHigherProtocol().connectionLost("Received FINACK"))
            self.transport.loseConnection()
            if self.__timely:
                self.__timely.cancel()
            self.__connected = 0
        else:
            pass
            ##print "Should not come here"
 
    def push_to_rcv_window(self,msgSeq,msgObj):
	###print "Inside push to rcv window checking offset now"
        #offset = msgSeq - self.__last_contig - 1
        offset = msgSeq - self.__curr_ackSeq - 1
        #print "Push_to_rcv_window: found the offset to be : ",offset, " and the seq number is : ",msgSeq
        if offset > RCVWINDOW and offset <0:
            ##print "Data outside rcv window"
            # DO NOTHING
            # It can be a delayed retransmit or 
            # its out of window we don't handle it
            return False
        else:
            ##print "Pushing data in rcv window"
            self.__rcvWindow.insert(offset,(msgSeq,msgObj))
            return True

    def slideRcvWindow(self,steps):
        ##print "Sliding receiver window, before: ",self.__rcvWindow
        self.__rcvWindow = self.__rcvWindow[steps:]
        self.__rcvWindow += ([(-1,'')]*steps) # add the remaining removed tuples
        ##print "Sliding receiver window, after: ",self.__rcvWindow

    def __handleDataRcvMessage(self,msgObj):
        if(self.__connected == 0):
            ##print "Connection Not Established Yet"
            return 
        self.__state = 4
        self.__exp_backoff = 0.05
        # Fixed : If server responds, it will not go through connection set up again and hence last_contig needs to be set to 
        # the seq number of the first data packet by server - 1 so that the system does not break
        if self.__connected == 1 and self.__last_contig == 0:
            self.__last_contig = msgObj.MessageSeq -1

        ##print "I have received Data, with serial number: ",msgObj.MessageSeq
        #if msgObj.MessageSeq <= self.__last_contig or msgObj.MessageSeq == 0:
        if msgObj.MessageSeq <= self.__curr_ackSeq or msgObj.MessageSeq == 0:
            ##print "Message is stale or has sequence 0, discard"
            return 
        pushed = self.push_to_rcv_window(msgObj.MessageSeq,msgObj)
        if(pushed):
            pass
            ##print "Message pushed to window successfully"
	else:
            pass
            ##print "Pushing to window unsuccessful - either msgseq too big or too small"
        #self.__curr_ackSeq = msgObj.MessageSeq
        # Check if the packet received is the next contiguous packet, if it is check if it 
        # completes a sequence, send the maximum number of contiguous packets up the layer
        # and slide the data rcv window
        logger.info("Harsh: "+str(self._addr)+" Got data on the receiver with sequence number: "+str(msgObj.MessageSeq)+" expected contiguous sequence number is :" + str(self.__curr_ackSeq+1))#str(self.__last_contig+1))
        #if (msgObj.MessageSeq == self.__last_contig+1):
        
        if (msgObj.MessageSeq == self.__curr_ackSeq+1):
           #logger.info("Harsh: "+str(self._addr)+" Got data on the receiver with contiguous sequence number: "+str(msgObj.MessageSeq))
           # TODO: Find a way to reset the timer. 
           ##print "Got the next contig packet resetting the timer"
           #print "Cancelled hb_timer"
           self.__hb_timer.cancel()
           #print "Restarted hb_timer"
           self.__hb_timer = Timer.OneshotTimer(lambda:self.checkData())
           self.__hb_timer.run(0.05)
           for seq in range(0,RCVWINDOW):
               if self.__rcvWindow[seq][0]==-1:
                   # reached end of max contiguous list present
                   break
           # set last contig as the maximum contig seq number present in rcv window and acknowledge that packet
           #self.__last_contig = self.__rcvWindow[seq-1][0] 
           #self.__curr_ackSeq = self.__last_contig
           self.__curr_ackSeq = self.__rcvWindow[seq-1][0]
           # print "Sending an ack with seq number: ",self.__currSeq, "and ack-ing max contiguously received seq number: ",self.__last_contig
           self.__handleConnectionMessages(7,msgObj)
           #Do window sliding
           for i in range(0,seq):
               rawData = self.__rcvWindow[i][1].Data
               ##print "Now Passing Data up the layer"
               self.getHigherProtocol().dataReceived(rawData)
           self.slideRcvWindow(i+1)
        #else: 
           #logger.info("Harsh: " +str(self._addr)+" Got data on the receiver with non contiguous sequence number: "+str(msgObj.MessageSeq)+ " expecting: "+str(self.__last_contig+1))
    
    def __handleAck(self,msgObj):
        self.__session_timer.cancel()
        self.__session_timer = Timer.OneshotTimer(lambda:self.checkSession())
        self.__session_timer.run(35)
        if self.__window == []:
            ##print "The window is empty, probably keep alive ACKs" 
            pass
        next_expected = self.top('Win')
        if msgObj.AckSeq < next_expected-1:
            ##print "Delayed/Duplicate ACK, discarding"
            return 
        ##print "I have received ACK for the data I sent, ack :",msgObj.AckSeq
        # Move the window forward if the seq number being ACK'd is the first
        # or higher in the list.Accodingly move the dataQueue forward too

        # If the ack'd packet is less than the first packet in the window check
        # if the ACK'd sequence is adjacent to the sequence at Window[0]. If yes
        # that means you have to send Window[0] again. 
        # Else just discard the ACK as it is a delayed ACK.
        if(self.__window != [] and msgObj.AckSeq >= next_expected):
            logger.info("Harsh: "+str(self._addr)+" Got the ACK on the sender, sliding window, seq no rcvd: "+str(msgObj.AckSeq))
            self.slideDataQueue(msgObj.AckSeq-(self.top('Win'))+1)
            self.slideWindow(msgObj.AckSeq)
        else:
            if(msgObj.AckSeq == next_expected-1):
                logger.info("Harsh: "+str(self._addr)+" Need to resend data with seq: "+str(next_expected))
                # Resend packet at window[0]
                ##print "Resending AckSeq+1th packet"
                #print "Helloo Helloo"
                #print "This is the data am sending: ",self.top('Data').__hash__()," this is the sequence ",self.top('Win')
                self.wrap_send_buffer(self.top('Data'),self.top('Win'))
               
                
    def slideWindow(self, ackSeq):
        ##print "Sliding window, before: ",self.__window
        for i in range(0,len(self.__window)):
            if(self.__window[i] == ackSeq):
                self.__window = self.__window[i+1:]
                break;
        ##print "after: ",self.__window
        self.processQueue()
       

    def slideDataQueue(self, steps):
        ##print "Sliding data queue, before:",self.__dataList
        self.__dataList= self.__dataList[steps:]
        self.__dataPoint -=steps
        ##print "after :",self.__dataList

    def top(self, listType):   
        if listType == 'Data':
            if(self.__dataList[0] == None):
                return -1
            else:
                return self.__dataList[0]
        if listType == 'Win':
            if(self.__window == []):
                return -1
            return self.__window[0]

    def isFull(self,listType):
        if listType == 'Data':
            if(False):
                ##print "dataList is full:"#,self.__dataList
                return True
            else:
                ##print "dataList is not full: "#,self.__dataList
                return False
        if listType == 'Win':
            if(len(self.__window) >= WINDOWSIZE):
                ##print "Window is full: "#,self.__window
                return True
            else:
                ##print "Window is not full: "#,self.__window
                return False
        # size of dataList can never be > DATALISTSIZE

    def push_to_list(self,listType,elem):
        ##print "inside push to list"
        if listType == 'Data':
            (self.__dataList).append(elem)
            #print "Check for duplicates here: Pushed to data list, datalist: ",self.__dataList
        if listType == 'Win':
            (self.__window).append(elem)
            #print "Check for duplicates here: Pushed to window, window: ",self.__window

    def next_element(self,listType):
        if listType == 'Data':
            if self.__dataPoint == len(self.__dataList):
                return None
            else:
                ##print "++++++++++++++++++++dataPoint Value++++++++++++++++",self.__dataPoint
                nxtElem = self.__dataList[self.__dataPoint]
                self.__dataPoint +=1
                return nxtElem
        if listType == 'Win':
            self.__winPoint +=1
            if (self.__winPoint > WINDOWSIZE) or (self.__winPoint == len(self.__window)):
                return None
            else:
                nxtElem = self.__window[winPoint]
                self.__winPoint +=1
                return nxtElem
   
    def check_for_frags(self,buf):
        chunkList = []
        buf_size = len(buf)
        if buf_size > 4000:
            tmp_str = ""
            for i in range(0, buf_size):
                tmp_str += buf[i]
                if (i+1)%4000 == 0:
                    chunkList.append(tmp_str)
                    tmp_str = ""
                elif i == buf_size - 1:
                    chunkList.append(tmp_str)
        else:
            chunkList.append(buf)
        return chunkList

    def write(self,buf):
        chunkList = self.check_for_frags(buf)
        for n in range(0,len(chunkList)):
            if (self.isFull('Data')):
                ##print "The internal data buffer is full, please try again in sometime"
                return
            else: 
                self.push_to_list('Data',chunkList[n])
                ##print "Pushed to dataList, current dataList : ", self.__dataList
        self.processQueue()


    def wrap_send_buffer(self, buf,seq):
        # Add a PTCL Header onto the buffer. Wrap it into a packet and send to C2C
        responseMessageBuilder = MessageData.GetMessageBuilder(PTCLMessage)
        responseMessageBuilder["Hash"].setData('0')
        responseMessageBuilder["MessageType"].setData("DATA")
        responseMessageBuilder["MessageSeq"].setData(seq)
        responseMessageBuilder["AckSeq"].setData(self.__curr_ackSeq)
        responseMessageBuilder["Data"].setData(buf)
        responseMessageBuilder["Hash"].setData(self.hash_it(responseMessageBuilder))
        logger.info("Harsh: "+str(self._addr)+" Sending Data and the sequence number I am sending is: "+str(seq))
        self.transport.writeMessage(responseMessageBuilder)
        ##print "Sent Data, with serial number: ",seq


    def processQueue(self):
        if(self.__connected == 0):
            ##print "=======================Not Connected===================="
            ##print "I have got a message to write but handshake not complete yet"
            if(self.__handshake == 0):
                ##print "No exisiting handshake in progress, initiating connection"
                self.__handleConnectionMessages(0)
            else:
                pass
                ##print "Handshake in progress, data added to queue"
                ##print "====================================================="
        else: 
            ##print "=========================Connected======================="
            if(self.isFull('Win')):
		pass               
		##print "Window is full, going to wait till packets are acknowledged"
            else: 
                while((self.isFull('Win'))!= True):
                    ##print "ProcessQueue: connected and window not full extracting next element"
                    nxtElem = self.next_element('Data')
                    ##print "Next Element : ",nxtElem
                    if(nxtElem != None):
                        self.__currSeq +=1 
                        self.push_to_list('Win',self.__currSeq)
                        #print "Pushed to Window, Current Window: ",self.__window
                        
                        #logger.info("Harsh: "+str(self._addr)+"Length of the next element: "+str(len(nxtElem))+" the hash is :" +str(hash(nxtElem))+" sequence number: "+str(self.__currSeq))
                        pkt = self.wrap_send_buffer(nxtElem,self.__currSeq)
                    else:
                        ##print "DataList is empty, nothing to send as of now"
                        break;
                ##print "========================================================="

    
    def writeMessage(self,msgFromTop=None):
        # When write message is called check for handshake state
        # if theres no handshake done, store the message from the
        # application layer and complete the handshake. Once done
        # send the message. Conversely if handshake is already done, 
        # just send the message
        self.write(msgFromTop.serialize())

    def checkWindow(self):
        if self.__dataList != [] or self.__window != []:
            #if self.__fin_timer:
             #   self.__fin_timer.cancel()
            self.__fin_timer = Timer.OneshotTimer(lambda:self.checkWindow())
            self.__fin_timer.run(0.1)
        else:
            if self.__connected == 1:
                if self.__finhandshake == 0:
                    self.__finhandshake = 1
                    self.__handleConnectionMessages(5)
                else:
                    pass
            else:
                pass

    def loseConnection(self):
        self.__fin_timer = Timer.OneshotTimer(lambda:self.checkWindow())
        self.__fin_timer.run(0.1)  
        #start FIN sequence
        """
        if self.__connected == 1:
            ##print "Got a FIN Request, there is a current connection, terminating the connection"
            if self.__finhandshake == 0:
                self.__finhandshake = 1 
                ##print "FIN handshake hasn't started yet, starting..."
                self.__handleConnectionMessages(5)
            else:
                ##print "FIN handshake already in progress"
                pass
        else:
            ##print "connection already ended"
            pass
        """

class MyPTCLNode(ClientApplicationServer):
    Protocol = PTCLProtocol

def createPtclStack(higherFactory):
    ptclFactory = MyPTCLNode()
    ptclFactory.setHigherFactory(higherFactory)
    return ptclFactory

