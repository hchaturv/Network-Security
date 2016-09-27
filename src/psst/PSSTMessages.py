'''
Created on Apr 2, 2016

@author: cyrusc
'''

from playground.network.message.StandardMessageSpecifiers import *
from playground.network.message.ProtoBuilder import MessageDefinition
from playground.network.message.definitions.Util import playgroundIdentifier

class PSSTHandshakeMessage(MessageDefinition):
  PLAYGROUND_IDENTIFIER = "playground.base.PSSTHandshakeMessage"
  MESSAGE_VERSION = "1.0"

  BODY = [
    ("MessageType", STRING),
    ("Cert_Chain", LIST(STRING)),
    ("Key", STRING),
    ("Nonce_S", STRING),
    ("Nonce_C", STRING),
    ("Data", STRING)
  ]

class PSSTDataMessage(MessageDefinition):
  PLAYGROUND_IDENTIFIER = "playground.base.PSSTDataMessage"
  MESSAGE_VERSION = "1.0"

  BODY = [
    ("MessageType", STRING),
    ("MAC", STRING),
    ("Data", STRING)
  ]