SimpleChat
written by Sean Liu


INTRODUCTION

SimpleChat is a chat application service that allows users to login through a client and chat through a server or through direct P2P message exchange. It utilizes non-persistent TCP connections and is built on standard Python 2.7 libraries.


HOW TO RUN

0. Confirm account and chat settings in credentials.txt and configuration.py, respectively.

1. Start the SimpleChat Server: python simplechat_server.py
	The server's IP address and port will be printed onto the console.

2. Start your SimpleChat Client(s): python simplechat_client.py <server IP-address> <server port number>
	
3. Follow the instructions for logging in, and start chatting! :)

4. Both server and client can be gracefully shut down by sending SIGINT signal, with Control-C. You may also shut down the client by logging out.


PROGRAM DESIGN

The main challenge was implementing the chat service with non-persistent connections. I accomplished this by having the chat server and chat client open and close a new TCP connection for every message sent. One exception is logging in, which I implemented using a "follow-on" method, since an immediate response from the server to a login request is easily implemented and necessary.

SimpleChat Server - simplechat_server.py
The server had one main task: to process all incoming messages from clients and respond accordingly. I used a non-blocking accept method with the select module, only accepting from listen_sock when it had a client waiting to connect. The server then puts the new socket into socket_q, a blocking queue from which worker threads would get the socket. I implemented a fixed number (THREAD_POOL_SIZE) of worker threads that would all compete to get a socket, read from it, and handle it appropriately. 
In addition, I used a separate thread to continually check for heartbeat messages, since these messages and responses are time-sensitive to the value stored in TIMEOUT.
To support a graceful exit, I made all threads daemons so that they would exit along with the main function after SIGINT is caught. When the server is shut down, all clients are notified.
The server used a dictionary to hold all the information of the users. Each key was a username, which mapped to another dictionary containing all the current information of that one user.

SimpleChat Client - simplechat_client.py
The client had two main tasks: to process all user commands and to respond to incoming messages from the server. Using a separate thread, processing user commands was a simple task of parsing user input commands and sending the appropriate messages. To respond to incoming messages, I also listened and accepted from a non-blocking listen_sock, but the client only used the main thread to accept incoming messages and process them. I made this decision because the client should not need a thread pool of worker threads, as its traffic should be nowhere near as heavy as that of the server.
In addition, I used a separate thread to continually send heartbeat messages to the server, since these messages are time-sensitive to the value stored in TIMEOUT.
To support a graceful exit, I made all threads daemons so that they would exit along with the main function after SIGINT is caught. A client will exit when the user logs out and when the server notifies it of shutdown. However, a client will continue to run if the user currently has other users in the address book--private messaging is still allowed.
The client used two dictionaries to keep track of important information: session_info to hold the current session address and the server's address, and address_book to hold the addresses of other users for private messaging.

Configuration - configuration.py
To make it easy to change configuration values, such as heartbeat timeout, maximum login attempts, and login block time, I placed all constants in configuration.py. Therefore, if a user/admin wants to change these settings, one just has to open this file and alter its values.

User Credentials - credentials.txt
credentials.txt contains the user account information. Each line contains a username and password, separated by whitespace.


COMMANDS

Online users can use the following commands:

- message: send a message through the server to another user.
	message [user] [message_text]

- broadcast: send a message through the server to all online users.
	broadcast [message_text]

- private: privately send a private message to a user through a P2P connection; the user must currently be in your address book; private messages can still be exchanged when server is down.
	private [user] [message_text]

- block: add a user to your blacklist; if user A has blacklisted user B, then B may no longer send messages to A nor see if A is online. (A may still message B and see whether B is online.)
	block [user]

- unblock: remove a user from your blacklist.
	unblock [user]

- online: check who else is currently online.
	online

- getaddress: request to add a user to your address book for private P2P messaging; if the the user agrees, then each user is added to each other's address book.
	getaddresss [user]

- removeaddress: remove user from address book; each user is removed from each other's address book.
	removeaddress [user]

- addressbook: check address book to see who you can privately message; when peers log out, they will be automatically removed from your address book.
	addressbook

- help: list all valid commands.
	help

- logout: log out user and terminate SimpleChat client session; notify server and P2P peers of logout.
	logout


UPCOMING FEATURES

- User statuses, e.g. available (default), busy, or invisible.

- Groups and group messaging.

