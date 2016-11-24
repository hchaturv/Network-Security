# Network-Security
Reliable &amp; Secure Layer over a make believe TCP Overlay network.

*This is a class project that I worked on in my Network Security Class.*


The goal of the project was to create a Reliable and Secure layer (much like TCP & SSL/TLS) on a make believe TCP Overlay network. The network was modelled on a peer to peer communication model with a central server, The Chaperone. The Chaperone would manage the routing and will try to simulate a real network. This infrastructure was provided to us before hand and was called the Playground Network. 


The playground network, as mentioned earlier, came with a basic network out of the box that gave no connection guarantees. The first leg of the project was to implement a Reliable layer that would ensure TCP-like connection guarantees like "What you send is what the receiver receives", the assumption being that there is no active adversary on the network. I was also a part of the PETF (you got it right, counterpart of the IETF- Internet Engineering Task Force) and was instrumental in formulating a standardized protocol to implement reliable layer(PTCL) and secure layer(PSST) for the playground network.


*PTCL (Playground Transmission Control Lite)*

*PSST (Playground Super Secure Transmission)*

*HTML rendered versions of the RFCs for both protocols can be viewed [here](https://cyrus-chua.github.io/)*


### Aims of PTCL were to-


1. Ensure data delivery

2. Ensure in-order delivery

3. Ensure message integrity 


**Key additions by PTCL Layer:**

* Added state to originally stateless connections by suggesting a three way handshake which would set up initial state variables. Also added a two state final completion state machine to initiate tear down of the connection.

* Added a packet acknowledgment procedure for the sender to ack the packets received successfully. This included ways of reporting loss of packets as well as an exponential back off mechanism to prevent network clogging. 

* Measures to prevent busy wait - sliding window protocol. The sender does not need to wait for per packet acks before sending new packets. 

* Integrity check - added hash to the the packet header as a means for the receiver to check message integrity.(hashing - SHA256)

* Ensured data delivery by suggesting packet retransmission based on historical acks or timeout mechanism. The timeout mechanism would also allow the sender/ receiver ways to decide if the connection has been droppped.  



### Aims of PSST were to standardize ways to achieve-

1. Confidentiality

2. Authenticity

3. Integrity



**Key additions by PSST Layer:**

* Encryption of messages to achieve message confidentiality (AES-CTR Mode). Like PTCL, PSST also had a state machine for handshake between the two conversing parties. The handshake would allow the two parties to establish each other's identities and by the end of the handshake, to come up with session keys that would be used to encrypt/decrypt data during the conversation. 

* Hashing the message using HMAC (SHA256 based) to allow the receiver to check message authenticity and integrity.

* Mutual authentication of conversing parties.

