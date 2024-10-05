‬
Threat Model and NIST’S Five Functions‬
‭ 
Identify‬
‭ I started my code development process by identifying what are the assets I want to protect, identify how an attack can be‬
‭ mounted, and identify policies related to securing this discussion platform.‬
‭ To begin with, in order to be able to identify the assets, it was important to consider the system architecture I wanted to‬
‭ implement towards a secure discussion platform. I chose to use a hybrid architecture where the system combines a‬
‭ client-server based system architecture and a peer to peer system architecture.‬
‭ The server is responsible for authentication, setting up and managing discussion groups, and relaying messages in‬
‭ encrypted form to other participants of a discussion group. However, there is a peer to peer mechanism as well which is‬
‭ triggered when a user enters a discussion group where the system administrator directly talks to the new client in order to‬
‭ distribute the cryptographic key. This approach enables centralised management of the discussion group while also‬
‭ making sure the key never hits the server.‬
‭ Moreover, because a discussion platform would utilise a network, it was also important to consider what type of transport‬
‭ layer protocol I was going to use. For the required functionality, I decided it would be appropriate to use a reliable,‬
‭ ordered and bi-directional data transfer protocol, TCP. The congestion avoidance algorithm of TCP makes the system‬
‭ more dependable which can be viewed as a security concept.‬
‭ A discussion platforms’ security concerns can be categorised under the communication security category. Therefore, I‬
‭ wanted my solution to address the main security concerns of communication category:‬
‭ 1.‬‭ Confidentiality:‬‭ Traffic must only be read by the sender and intended recipient.‬
‭ 2.‬‭ Anonymity‬‭ : Only the sender and intended recipient should know the existence of a message.‬
‭ 3.‬‭ Authentication:‬‭ Both the sender and receiver can demonstrate they are who they say they are.‬
‭ With the above security concerns identified above, my primary objective was to protect the end user by protecting the‬
‭ content of the messages users send, the status of a user’s participation in a discussion, and a user’s username and‬
‭ password details that will be used for authentication. In addition to these assets, another asset this system has is the ability‬
‭ of the system to remain operational. But, this isn’t as critical as confidentiality, anonymity, and authentication. Therefore,‬
‭ my secondary objective is to protect the server from being subject to distributed denial of service attacks.‬
‭ In order to achieve these goals, I came up with a system policy to establish a zero-knowledge and zero-trust discussion‬
‭ platform system. The system achieves zero-knowledge property by treating discussions as single session discussion where‬
‭ no content is stored anywhere and is only displayed on a client’s terminal. The system only records username and‬
‭ password details for authentication which by itself is not enough to access a discussion channel as a 2 factor‬
‭ authentication scheme is in place. Moreover, the system establishes zero-trust property by having the sender client encrypt‬
‭ every interaction which is verified by the receiver of the message to catch malicious actors. This is done through a‬
‭ symmetric key encryption. These policies maximise the confidentiality and privacy of the end user.‬
‭ The attackers can mount an attack through different pathways which we identify now in order to deploy countermeasures.‬
‭ The system implementation uses libraries therefore, an attacker can perform supply chain attacks by embedding malicious‬
‭ code into these libraries to exploit the system later through a backdoor. The attackers might attack the keystores and trust‬
‭ stores to compromise the tunnelling security mechanism, which will be discussed in the protect section, in order to‬
‭ perform eavesdropping attacks to read the messages of users. Finally, the attackers might perform hijacking,‬
‭ impersonation, and denial of service attacks. In the next section we discuss how we can protect our system against these‬
‭ attacks.‬

‭ Detect‬
‭ Cryptography is vital for detecting anomalies in an exchange. I use the TLS security mechanism in order to address the security‬
‭ concerns of communication security. It achieves confidentiality by hiding the data through a tunnelling mechanism so that‬
‭ attackers can’t read the content of the message or the communication details of the message. It also provides authentication to‬
‭ the client by the certificate mechanism. One limiting factor of my system is the server certificate is self signed, however, in a‬
‭ real application this can be exchanged with a CA signed certificate. It also provides integrity guarantees as it detects any‬
‭ tampering of data took place.

‭ Protect‬
‭ In order to protect the users of the system, we put them in charge. That is to say that the server isn’t capable of seeing any‬
‭ messages as they will be encrypted. The keys are exchanged directly between users in band, again through a SSLSocket‬
‭ as we don’t want any attacker from being able to snatch the keys off the wire. The in-band key management system‬
‭ increases system usability as an out of band delivery mechanism can make communication infeasible or too tedious.‬
‭ Moreover, the discussion group administrator is given a code which other parties need in order to join this discussion‬
‭ group. The user can choose to share this code with who they want in a secure way using other mechanisms (other end to‬
‭ end encrypted apps or more likely a physical exchange). Once a user joins, no individual message is tagged with a‬
‭ username, the end user just sees somebody in a group sent a message.‬
‭ These approaches maximise the privacy of a user as what they can say can not be attributed to any specific group‬
‭ member and people who choose to join a discussion platform this way explicitly has to think about trusting the admin and‬
‭ the admin has to think about explicitly trusting the other clients for invitation code sharing. This implies that the user has‬
‭ more information about what data will be revealed to who and none of their data will be known to a third party.‬
‭ Moreover, the system protects itself against malicious attacks through an integrated server firewall. This firewall has a list‬
‭ of IP’s that are known to be of malicious sources and they are not allowed to be connected to the server. Moreover, the‬
‭ firewall has a rate limiting policy where in order for a connection to be allowed, the last connection should have been‬
‭ made at least 0.5 seconds ago. This is done in order to prevent DDOS attacks. The firewall also has a logic where it‬
‭ doesn’t allow more than 10 connections per an IP address to prevent a DOS attack.‬
‭ 
Respond‬
‭ The users, if they feel compromised, can respond to any sense of danger by terminating their connection because the‬
‭ system only works on a single session basis. No chat data is stored. Therefore my aim was to increase user awareness of‬
‭ what is going on in the discussion platform. To realize this goal, I made sure newly joined users don’t have access to‬
‭ previous chats, or who is on the server which is part of our anonymity policy. If users don’t recognize A warning message‬
‭ is broadcasted to all users in the discussion group when a new client joins the group along with the username , and if users‬
‭ don’t recognize this username, they can choose to end their connections and participate in that discussion no more.‬
‭ 
Recover‬
‭ If an attack is detected, our policy would be to switch to another similar system (assuming it exists) which uses different‬
‭ but robust security mechanisms until the pathway of the latest attack is determined and blocked through additional‬
‭ countermeasures. Then, the system can be re-deployed after necessary changes have been made.‬
‭
