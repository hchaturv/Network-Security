'''
Created on Apr 2, 2016

@authors:

Xiao Chong(Cyrus) Chua
Information Security Institute 
Johns Hopkins University

Harsh Chaturvedi
Information Security Institute
Johns Hopkins University

Under the Guidance of : 

Dr Seth Neilson
Johns Hopkins University
'''

import logging
logger = logging.getLogger(__name__)
from playground.network.psst.PSSTMessages import PSSTHandshakeMessage, PSSTDataMessage
from playground.network.common import PlaygroundAddress, Packet
from playground.network.common import SimpleMessageHandlingProtocol, StackingProtocolMixin
from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.client.ClientApplicationTransport import StackingTransportMixin
from playground.network.client.ClientApplicationServer import ClientApplicationServer
from playground.network.client import ClientBase
from playground.network.message import MessageData
from playground import playgroundlog
from playground.crypto import X509Certificate
from playground.network.common import Timer

from illuminati.protocols.ptcl.Protocol import PtclServerStack, PtclClientStack

from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import HMAC, SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random
from Crypto.Cipher.PKCS1_OAEP import PKCS1OAEP_Cipher

KEY_PEM_FILE_PATH = "certs/cyrus.key" #E.g.: ~/key.pem
ROOT_CERT_PATH = "certs/root.cert" #E.g.: ~/root.cert

NOTCONNECTED = 0 
HANDSHAKE = 1
CONNECTED = 2
BLOCK = 1 # Change this to 1 if you're using an IP address from a block of IP
BLOCKCERTPATH = "certs/underdog_signed.cert" #Put the block cert path right here, the code will pick it up
IPCERTPATH = "certs/ipaddressCyrus.cert" #Put the individual IP cert path here
ISBUFFERED = 0 # Macro to state if there is buffered data present to be sent after handshake is complete
CLIENT = 1
SERVER = 2
HELLO = 1 # HELLO Received
CHALLENGE = 2 # CHALLENGE Received
CHALRESP = 3 # CHALLENGE RESPONSE Received
RESPONSE = 4 # RESPONSE Received
DATA = 5 # DATA sending state
FIN = 6

class PSSTProtocol(SimpleMessageHandlingProtocol, StackingProtocolMixin, StackingTransportMixin):

    def __init__(self,factory,addr):
        self.__state = 0    # current state of the connection
        self.__messageFromTop = "" # Message sent by the top layer
        self.__connected = 0  # Handshake is complete or not started
        self.__handshake = 0 # Three way handshake started but not complete
        self.__session_timer = None
        #self.__behavior = 0
        self.__nonce = "" #This is my nonce
        self.__noncePeer = "" #This is my peer's nonce
        #self.__nonceC = 0
        #self.__nonceS = 0
        self.__sym_key = "" #This is the sym key thats generated locally and sent to the peer
        self.__peer_sym_key = "" # This is the sym key thats sent by the peer and has to be used for further enc
        self.__handshakeEncrypter = None
        self.__handshakeDecrypter = None
        self.__aesEncrypter = None
        self.__aesDecrypter = None
        self.__bufferedDataList = []
        self.__bufferedDataReceivedList = []
        SimpleMessageHandlingProtocol.__init__(self, factory,addr)
        self.registerMessageHandler(PSSTHandshakeMessage,self.__psstHandshakeMessageHandler)
        self.registerMessageHandler(PSSTDataMessage,self.__psstDataMessageHandler)

    """
    This function handles PSST Handshake messages.
    """
    def __psstHandshakeMessageHandler(self, protocol, msg):
        msgObj = msg.data()
        if msgObj.MessageType == "HELLO":
            self.__connected = HANDSHAKE
            self.__state = HELLO
            self.__process_handshake(HELLO,msgObj)
        elif msgObj.MessageType == "CHALLENGE":
            self.__state = CHALLENGE
            self.__process_handshake(CHALLENGE, msgObj)
            self.__state = HANDSHAKE
        elif msgObj.MessageType == "CHALLENGE/RESPONSE":
            self.__state = CHALRESP
            self.__process_handshake(CHALRESP, msgObj)
            self.__connected = CONNECTED
            self.__state = DATA
        elif msgObj.MessageType == "RESPONSE":
            self.__state = RESPONSE
            self.__process_handshake(RESPONSE, msgObj)
            self.__connected = CONNECTED
            self.__state = DATA
        else:
            logger.info("PSST Handshake: Invalid Message Type %s" %(msgObj.MessageType)) 
        pass

    """
    This function handles PSST Data messages.
    """
    def __psstDataMessageHandler(self, protocol, msg):
        if not (self.__connected == CONNECTED and self.__state == DATA):
            return
        msgObj = msg.data()
        if msgObj.MessageType == "DATA":
            raw_data = msgObj.Data
            logger.info("Data Transmission: Received data " + raw_data)
            hmac = msgObj.MAC
            if self.__verifyHMAC(self.__peer_sym_key, "DATA"+raw_data, hmac):
                decrypted_data = self.__decrypt(raw_data, self.__aesDecrypter)
                self.getHigherProtocol().dataReceived(decrypted_data)
            else:
                #print "HMAC verification failed: terminate connection"
                return
        elif msgObj.MessageType == "FIN":
            hmac = msgObj.MAC
            if self.__verifyHMAC(self.__peer_sym_key, "FIN", hmac):
                hmac = self.__generateHMAC(self.__sym_key, "FINACK")
                finack_msg = self.__buildDataMessage("FINACK", hmac, "")
                self.__send(finack_msg)
                self.getHigherProtocol().connectionLost("Received FIN")
                self.transport.loseConnection()
            else:
                return
        elif msgObj.MessageType == "FINACK":
            hmac = msgObj.MAC
            if self.__verifyHMAC(self.__peer_sym_key, "FINACK", hmac):
                self.getHigherProtocol().connectionLost("Received FINACK")
                self.transport.loseConnection()
            else:
                return

    """
    This function initiates the secure layer handshake. Moves connection state from
    Not Connected to Handshake.
    Insert cert or cert chain based on whether it's an IP from a block or an individual IP
    """
    def __initiateHandshake(self):
        #print "initiate handshake"
        #self.__behavior = CLIENT
        self.__connected = HANDSHAKE
        cert_chain = ["", "", ""]
        with open(IPCERTPATH) as cert_file:
            cert_chain[0] = cert_file.read()
        if BLOCK == 1:
            with open(BLOCKCERTPATH) as block_cert_file:
                cert_chain[1] = block_cert_file.read()
        hello_msg = self.__buildHandshakeMessage("HELLO",cert_chain,"","","","")
        logger.debug("PSST Handshake: Handshake initiated, sending HELLO message")
        self.__send(hello_msg)
        self.__generateRSADecrypter()

    def __process_handshake(self, msgType,msgObj):
        #print "process_handshake"
        if msgType == HELLO:
            #print "received HELLO"
            #Server is processing handshake message.
            my_cert_chain = ["", "", ""]
            response = self.__verifyCertChain(msgObj.Cert_Chain)
            #print "cert chain verification:", response
            if (response == True):
            #if (True):
                #print "cert chain successfully verfied, building challenge message"
                logger.info("PSST Handshake: Certs from client validated, sending CHALLENGE")
                self.__generateNonce()
                with open(IPCERTPATH) as ip_cert_file:
                    my_cert_chain[0] = ip_cert_file.read()
                if BLOCK == 1:
                    with open(BLOCKCERTPATH) as block_cert_file:
                        my_cert_chain[1] = block_cert_file.read()
                self.__generateRSAEncrypter(msgObj.Cert_Chain[0])
                #print self.__nonce
                encNonceServer = self.__encrypt(self.__nonce, self.__handshakeEncrypter)
                while "" in my_cert_chain:
                    my_cert_chain.remove("")
                challenge_msg = self.__buildHandshakeMessage("CHALLENGE",my_cert_chain,"",encNonceServer,"","")
                self.__send(challenge_msg)
                #print "message sent"
                self.__generateRSADecrypter()
            else:
                logger.info("PSST Handshake: Invalid Certs from client, exiting")
                return
        elif msgType == CHALLENGE:
            #print "received CHALLENGE"
            #Client is processing handshake message.
            response = self.__verifyCertChain(msgObj.Cert_Chain)
            #print "cert chain verification:", response
            if (response == True):
            #if (True):
                logger.info("PSST Handshake: Certs from server validated, sending CHALLENGE RESPONSE")
                self.__generateNonce()
                self.__generateKey()
                peerPublicKey = self.__getPubKeyFromCert(msgObj.Cert_Chain[0])
                #self.__handshakeEncrypter = PKCS1OAEP_Cipher(peerPublicKey,None,None,None)
                self.__generateRSAEncrypter(msgObj.Cert_Chain[0])
                encNonceClient = self.__encrypt(self.__nonce, self.__handshakeEncrypter)
                self.__noncePeer = self.__decrypt(msgObj.Nonce_S, self.__handshakeDecrypter)
                encNonceServer = self.__encrypt(self.__noncePeer, self.__handshakeEncrypter)
                encKeyClient = self.__encrypt(self.__sym_key,self.__handshakeEncrypter)
                chalresp_msg = self.__buildHandshakeMessage("CHALLENGE/RESPONSE",[],encKeyClient,encNonceServer,encNonceClient,"")
                self.__send(chalresp_msg)
                #print "challengeresponse message sent"
            else:
                logger.info("PSST Handshake: Invalid Certs from server, exiting")
                return
        elif msgType == CHALRESP:
            #print "received CHALLENGE/RESPONSE"
            #Server is processing handshake message.
            nonceTemp = self.__decrypt(msgObj.Nonce_S, self.__handshakeDecrypter)
            if nonceTemp != self.__nonce:
                logger.info("The server nonce sent by the client does not match the one the server originally sent")
                #print "nonce comparsion failed:", nonceTemp, self.__nonce
                return
            self.__generateKey()
            self.__peer_sym_key = self.__decrypt(msgObj.Key, self.__handshakeDecrypter)
            self.__noncePeer = self.__decrypt(msgObj.Nonce_C, self.__handshakeDecrypter)
            encNonceClient = self.__encrypt(self.__noncePeer, self.__handshakeEncrypter)
            encKeyServer = self.__encrypt(self.__sym_key, self.__handshakeEncrypter)
            response_msg = self.__buildHandshakeMessage("RESPONSE",[],encKeyServer,"",encNonceClient,"") 
            self.__send(response_msg)
            #print "response message sent"
            self.__connected = CONNECTED
            #print  "Server entered CONNECTED state"
            self.__generateAESObj(self.__sym_key, self.__nonce, "encrypter")
            self.__generateAESObj(self.__peer_sym_key, self.__noncePeer, "decrypter")
 
        elif msgType == RESPONSE:
            #print "received RESPONSE"
            #Client is processing handshake message.
            nonceTemp = self.__decrypt(msgObj.Nonce_C, self.__handshakeDecrypter)
            if nonceTemp != self.__nonce:
                logger.info("The client nonce sent by the server does not match the one the client originally sent")
                #print "nonce comparsion failed:", nonceTemp, self.__nonce
                return 
            self.__peer_sym_key = self.__decrypt(msgObj.Key, self.__handshakeDecrypter)
            self.__connected = CONNECTED
            #print "Client entered CONNECTED state"
            self.__generateAESObj(self.__sym_key, self.__nonce, "encrypter")
            self.__generateAESObj(self.__peer_sym_key, self.__noncePeer, "decrypter")

    """
    This function takes in a serialized upper layer message for processing. Two scenarios possible"
    1. If handshake has not started yet, initiate handshake
    2. Handshake initiated state NOT connected, wait for handshake to be complete
    3. Handshake complete, state connected. Send data.
    """
    def write(self, serialized_msg_from_top):
        #print "write"
        self.__pushToList(serialized_msg_from_top)
        logger.info("Message put in buffer, checking connection state")
        if (self.__connected == NOTCONNECTED): # No existing connection initiating handshake
            logger.info("PSST Handshake: Starting handshake")
            self.__initiateHandshake()
            Timer.callLater(0.05, lambda:self.__checkConnectionState())
        elif (self.__connected == HANDSHAKE): # Handshake still not complete, buffer the messages
            logger.info("PSST Handshake: Handshake not complete")
            Timer.callLater(0.05, lambda:self.__checkConnectionState())
        elif (self.__connected == CONNECTED):
            logger.info("PSST Handshake: Hanshake now complete, ready to send buffered messages")
            self.__processBuffer()
        else:
            logger.debug("PSST Handshake: Unknown connected state reached")

    def __initiateFIN(self):
        hmac = self.__generateHMAC(self.__sym_key, "FIN")
        fin_msg = self.__buildDataMessage("FIN", hmac, "")
        self.__send(fin_msg)
        self.__state = FIN
        Timer.callLater(2,lambda:self.__checkConnectionState())

    def __pushToList(self,serialized_msg):
        self.__bufferedDataList.append(serialized_msg)

    def __checkConnectionState(self):
        if self.__connected == CONNECTED and self.__state == DATA:
            self.__processBuffer()
        elif self.__connected == CONNECTED and self.__state == FIN:
            self.transport.loseConnection()
            self.getHigherProtocol().connectionLost("Sent FIN, Timed out")
        else:
            Timer.callLater(0.05, lambda:self.__checkConnectionState())

    def __processBuffer(self):
        logger.info("Data Transmission started")
        while len(self.__bufferedDataList) > 0:
            msg = self.__bufferedDataList.pop(0)
            encrypted_data = self.__encrypt(msg, self.__aesEncrypter)
            hmac = self.__generateHMAC(self.__sym_key, "DATA"+encrypted_data)
            encrypted_psst_msg = self.__buildDataMessage("DATA", hmac, encrypted_data)
            self.__send(encrypted_psst_msg)
            logger.info("Data Transmission: Sent data encrypted data of" + msg)

    """
    This function takes in a message object and sends it to the lower layer.
    msg: a handshake or data message object built using __buildHandshakeMessage() or __buildDataMessage().
    """
    def __send(self, msg):
        self.transport.writeMessage(msg)

    """
    This function is called by the upper later when to terminate a PSST connection.
    Teardown sequence should be initiated here.
    """
    def loseConnection(self):
        self.__initiateFIN()

    """
    This function takes in parameters for different message fields in a PSST handshake message.
    Returns an unserialized message object.
    """
    def __buildHandshakeMessage(self, msg_type, cert_chain, key, nonce_s, nonce_c, data):
        message_builder = MessageData.GetMessageBuilder(PSSTHandshakeMessage)
        message_builder["MessageType"].setData(msg_type)
        message_builder["Cert_Chain"].setData(cert_chain)
        message_builder["Key"].setData(key)
        message_builder["Nonce_S"].setData(nonce_s)
        message_builder["Nonce_C"].setData(nonce_c)
        message_builder["Data"].setData(data)
        return message_builder

    """
    This function takes in parameters for different message fields in a PSST data message.
    Returns an unserialized message object.
    """
    def __buildDataMessage(self, msg_type, mac, data):
        message_builder = MessageData.GetMessageBuilder(PSSTDataMessage)
        message_builder["MessageType"].setData(msg_type)
        message_builder["MAC"].setData(mac)
        message_builder["Data"].setData(data)
        return message_builder

    """
    This function generates a HMAC, given a data string.
    """
    def __generateHMAC(self, key, data):
        hm = HMAC.new(key, digestmod=SHA256)
        hm.update(data)
        return hm.hexdigest()

    def __verifyHMAC(self, key, data, mac):
        hm = HMAC.new(key, digestmod=SHA256)
        hm.update(data)
        if mac != hm.hexdigest():
            return False
        elif mac == hm.hexdigest():
            return True


    def __getPubKeyFromCert(self, cert_string):
        cert = X509Certificate.loadPEM(cert_string)
        pk_blob = cert.getPublicKeyBlob()
        pk = RSA.importKey(pk_blob)
        return pk

    """
    This function generates a list of certs, given a list of cert file names.
    """
    def __getCertChain(self, cert_file_names_list):
        cert_strings_list = []
        for cert in cert_file_names_list:
            with open(cert) as cert_file:
                cert_string = cert_file.read()
            cert_strings_list.append(cert_string)
        return cert_strings_list

    def __verifyCert(self, cert, signer_cert):
        pk_bytes = signer_cert.getPublicKeyBlob()
        pk = RSA.importKey(pk_bytes)
        rsaVerifier = PKCS1_v1_5.new(pk)
        data_to_verify = cert.getPemEncodedCertWithoutSignatureBlob()
        hasher = SHA256.new()
        hasher.update(data_to_verify)
        result = rsaVerifier.verify(hasher, cert.getSignatureBlob())
        return result

    def __verifyCertChain(self, cert_strings_list):
        with open(ROOT_CERT_PATH) as root_cert_file:
            root_cert_string = root_cert_file.read()
        individual_ip_cert = X509Certificate.loadPEM(cert_strings_list[0])
        addr = self.transport.getPeer().host
        if individual_ip_cert.getSubject()["commonName"] != str(addr):
            #print "indv ip cert common name", individual_ip_cert.getSubject()["commonName"]
            return False
        if cert_strings_list[1]!="":
            block_ip_cert = X509Certificate.loadPEM(cert_strings_list[1])
            if block_ip_cert.getSubject()["commonName"] not in str(addr):
                #print "block ip cert common name", block_ip_cert.getSubject()["commonName"]
                return False
        else:
            block_ip_cert = ""
        root_cert = X509Certificate.loadPEM(root_cert_string)
        if block_ip_cert == "" or block_ip_cert.getSubject() == root_cert.getSubject():
            cert = individual_ip_cert
            if (cert.getIssuer() != root_cert.getSubject()):
                #print "failure 0.1"
                return False
            if self.__verifyCert(cert, root_cert) == False:
                #print "failure 0.2"
                return False
        else:
            cert1 = individual_ip_cert
            cert2 = block_ip_cert
            if (cert1.getIssuer() != cert2.getSubject() or cert2.getIssuer() != root_cert.getSubject()):
                #print "failure 1", "\n", cert1.getSubject(), "\n", cert1.getIssuer(), "\n", cert2.getSubject(), "\n", cert2.getIssuer(), "\n", root_cert.getSubject()
                return False
            if (self.__verifyCert(cert1, cert2) or self.__verifyCert(cert2, root_cert)) == False:
                #print "failure 2"
                return False
        return True

    """
    Generates 32 bytes key.
    """
    def __generateKey(self):
        random_generator = Random.new()
        key = random_generator.read(32)
        self.__sym_key = key

    """
    Generates 16 bytes nonce, which will be used as IV when encrypting messages at the respective sides.
    """
    def __generateNonce(self):
        random_generator = Random.new()
        nonce = random_generator.read(16)
        self.__nonce = nonce

    def __generateRSAEncrypter(self, cert_string):
        peer_pk = self.__getPubKeyFromCert(cert_string)
        peer_rsa_encrypter = PKCS1OAEP_Cipher(peer_pk, None, None, None)
        self.__handshakeEncrypter = peer_rsa_encrypter

    def __generateRSADecrypter(self):
        with open(KEY_PEM_FILE_PATH) as key_pem_file:
            key_bytes = key_pem_file.read()
        key = RSA.importKey(key_bytes)
        rsa_decrypter = PKCS1OAEP_Cipher(key, None, None, None)
        self.__handshakeDecrypter = rsa_decrypter

    def __generateAESObj(self, key, IV, aes_obj_type):
        IV_asCtr = Counter.new(128, initial_value=int(IV.encode('hex'), 16))
        aes_crypto = AES.new(key, counter=IV_asCtr, mode=AES.MODE_CTR)
        if aes_obj_type == "encrypter":
            self.__aesEncrypter = aes_crypto
        elif aes_obj_type == "decrypter":
            self.__aesDecrypter = aes_crypto

    """
    Returns AES256-CTR encrypted string.
    """
    def __encrypt(self, plaintext, encrypter_obj):
        ciphertext = encrypter_obj.encrypt(plaintext)
        return ciphertext

    """
    Returns AES256-CTR decrypted string.
    """
    def __decrypt(self, ciphertext, decrypter_obj):
        plaintext = decrypter_obj.decrypt(ciphertext)
        return plaintext

    def writeMessage(self,msg_from_top=None):
        #print "writeMessage"
        self.write(msg_from_top.serialize())

    def connectionMade(self):
        self.getHigherProtocol().makeConnection(self)

class MyPSSTNode(ClientApplicationServer):
    Protocol = PSSTProtocol

def createPsstClientStack(higher_factory):
    psst_factory = MyPSSTNode()
    psst_factory.setHigherFactory(higher_factory)
    return PtclClientStack(psst_factory)

def createPsstServerStack(higher_factory):
    psst_factory = MyPSSTNode()
    psst_factory.setHigherFactory(higher_factory)
    return PtclServerStack(psst_factory)
    
"""
def createPsstStack(higher_factory):
    psst_factory = MyPSSTNode()
    psst_factory.setHigherFactory(higher_factory)
    return psst_factory
"""
