# SimpleChat Server
# 
# Written by Sean Liu


import socket
import select
import signal
import sys
from time import sleep
from threading import Thread
from Queue import Queue
from sets import Set
import datetime as dt
from configuration import *


users = {}              # all users
socket_q = Queue()      # queue for accepted sockets to read from


def sighandler(signum, frame):
    """graceful exit"""
    print 'Shutting down SimpleChat Server...\n'
    for username in users:
        user = users[username]

        # alert every online user of server termination
        if user['online_time']:
            try:
                end_sock = new_socket()
                end_sock.connect(user['address'])
                end_sock.send(SERVER_DOWN)
                end_sock.close()
            except:
                print 'ERROR: failed to notify %s (%s) of shutdown.' \
                %(user['username'], user['address'][0])
    
    print '------------------SimpleChat Server closed.--------------------\n'
    sys.exit(1)


def initialize_users(user_filename):
    """read accounts file and initialize users dict"""
    user_file = open(user_filename, 'r')
    user_line = user_file.readline().rstrip()
    while user_line != '':
        user_info = user_line.split(' ')
        user = make_user(user_info)
        users[user_info[0]] = user
        user_line = user_file.readline().rstrip()


def make_user(user_info):
    """creates a dict containing a user's information"""
    user = {}
    user['username'] = user_info[0] 
    user['password'] = user_info[1]
    user['blacklist'] = Set()   
    user['login_attempts'] = 0 
    user['address'] = None              # (ip_address, port)
    user['block_time'] = 0              # time when user was blocked
    user['offline_msg_list'] = Queue()  # list of strings: <sender> <msg>
    user['online_time'] = 0             # time of user's last login/heartbeat     
    return user


def send_packet(send_address, packet):
    """sends packet to send_address"""
    try:
        send_sock = new_socket()
        send_sock.connect(send_address)
        send_sock.send(packet)
        send_sock.close()
    except:
        print '> ERROR: failed to send message to IP %s.\n%s\n' \
        %(send_address[0], packet)


# thread
def check_heartbeat():
    """checks whether each user is still online"""
    while 1: 
        for username in users:
            user = users[username]
            if not user['online_time']:
                continue
            now = dt.datetime.now()
            try:
                if now-user['online_time'] > dt.timedelta(seconds=TIMEOUT):
                    send_packet(user['address'], LOGOUT_TIMED_OUT)
                    logout_user(user)
            except:
                continue


# thread
def process_incoming_packets():
    """reads from client_sock and handles the request"""
    while 1:
        conn = socket_q.get()
        packet = conn.recv(BUF_SIZE)
        p_contents = packet.split(' ', 1)
        p_type = p_contents[0]

        if p_type == LOGIN:
            contents = p_contents[1].split(' ', 3)
            username = contents[0]
            password = contents[1]
            user_ip = contents[2]
            user_port = contents[3]
            handle_login(username, password, conn, (user_ip, int(user_port)))
            return

        conn.close()

        if p_type == LOGOUT:
            username = p_contents[1]
            handle_logout(username)

        elif p_type == HEARTBEAT:
            username = p_contents[1]
            handle_heartbeat(username)

        elif p_type == SEND_MSG:
            contents = p_contents[1].split(' ', 2)
            receiver_name = contents[0]
            sender_name = contents[1]
            msg = contents[2]
            handle_send_msg(receiver_name, sender_name, msg)

        elif p_type == BROADCAST:
            contents = p_contents[1].split(' ', 1)
            sender_name = contents[0]
            msg = contents[1]
            handle_broadcast(sender_name, msg)

        elif p_type == BLOCK_USER:
            contents = p_contents[1].split(' ', 1)
            target_name = contents[0]
            blocker_name = contents[1]
            handle_block(target_name, blocker_name)

        elif p_type == UNBLOCK_USER:
            contents = p_contents[1].split(' ', 1)
            target_name = contents[0]
            unblocker_name = contents[1]
            handle_unblock(target_name, unblocker_name)

        elif p_type == CHECK_ONLINE:
            username = p_contents[1]
            handle_check_online(username)

        elif p_type == GET_ADDR:
            contents = p_contents[1].split(' ', 1)
            target_name = contents[0]
            asker_name = contents[1]
            handle_get_address_ask(target_name, asker_name)

        elif p_type == GET_ADDR_OK:
            contents = p_contents[1].split(' ', 1)
            asker_name = contents[0]
            target_name = contents[1]
            handle_get_address_ok(target_name, asker_name)

        elif p_type == GET_ADDR_FAIL:
            contents = p_contents[1].split(' ', 1)
            asker_name = contents[0]
            target_name = contents[1]
            handle_get_address_fail(target_name, asker_name)            

        else:
            print 'ALERT: received unrecognized packet:\n%s\n.' %packet


def handle_login(username, password, conn, user_addr):
    """handles a login request"""
    if not (username in users):
        conn.send(INVALID_USERNAME)
        conn.close()
        return
    
    user = users[username]

    if is_blocked(user):
        conn.send(USER_BLOCKED)
        conn.close()
        return       

    user['login_attempts'] += 1 

    # successful login
    if password == user['password']:
        conn.send(LOGIN_OK)
        conn.close()
        login_user(user, user_addr)
        return

    # bad password
    if user['login_attempts'] < MAX_LOGIN_ATTEMPTS:
        conn.send(INVALID_PASSWORD)
        conn.close()
        return

    # send block message
    conn.send(USER_BLOCKED)
    conn.close()
    user['block_time'] = dt.datetime.now()

    # force logged in user to sign off
    if user['online_time']:
        send_packet(user['address'], USER_BLOCKED)
        logout_user(user)


def handle_logout(username):
    """handles a logout request"""
    if username in users:
        logout_user(users[username])


def handle_heartbeat(username):
    """updates a user's heartbeat"""
    if username in users:
        user = users[username]
        if user['online_time']:
            user['online_time'] = dt.datetime.now()


def handle_send_msg(receiver_name, sender_name, msg_text):
    """handles a request to send a message"""
    sender = users[sender_name]

    # check whether receiver is valid
    if not (receiver_name in users):
        msg = ' '.join((INVALID_RECEIVER, receiver_name))
        send_packet(sender['address'], msg)
        return

    # check whether sender is blocked
    receiver = users[receiver_name]
    if sender_name in receiver['blacklist']:
        msg = ' '.join((MSG_BLOCKED, receiver_name))
        send_packet(sender['address'], msg)
        return

    # send message
    msg_contents = ' '.join((sender_name, msg_text))
    if not receiver['online_time']: 
        receiver['offline_msg_list'].put(msg_contents)
        ack = ' '.join((OFFLINE_MSG_OK, receiver_name))
    else:
        msg = ' '.join((CHAT_MSG, msg_contents))
        send_packet(receiver['address'], msg)
        ack = ' '.join((CHAT_MSG_OK, receiver_name))
    send_packet(sender['address'], ack)


def handle_broadcast(sender_name, msg_text):
    """handles a broadcast request"""
    bcast_blocked = False

    for username in users:

        # no need to broadcast to self
        if username == sender_name:
            continue

        receiver = users[username]

        # check whether sender is blacklisted
        if sender_name in receiver['blacklist']:
            bcast_blocked = True
            continue

        # send broadcast message
        msg_contents = ' '.join((sender_name, msg_text))
        if receiver['online_time']: 
            msg = ' '.join((CHAT_MSG, msg_contents))
            send_packet(receiver['address'], msg)

    # report back to sender
    sender = users[sender_name]
    if bcast_blocked:
        send_packet(sender['address'], BROADCAST_BLOCKED)
    else:
        send_packet(sender['address'], BROADCAST_OK)


def handle_block(target_name, blocker_name):
    """handles a block request"""
    blocker = users[blocker_name]

    # check for valud block target
    if target_name == blocker_name or not (target_name in users):
        msg = ' '.join((BLOCK_INVALID, target_name))
        send_packet(blocker['address'], msg)
        return

    # check whether target is already blocked
    if target_name in blocker['blacklist']:
        msg = ' '.join((ALREADY_BLOCKED, target_name))

    # block target
    else:
        blocker['blacklist'].add(target_name)
        msg = ' '.join((BLOCK_OK, target_name))
    
    # block response
    send_packet(blocker['address'], msg)


def handle_unblock(target_name, unblocker_name):
    """handles an unblock request"""
    unblocker = users[unblocker_name]

    # check whether target is currently blocked
    if not (target_name in unblocker['blacklist']):
        msg = ' '.join((UNBLOCK_INVALID, target_name))

    # block target
    else:
        unblocker['blacklist'].discard(target_name)
        msg = ' '.join((UNBLOCK_OK, target_name))
    
    # unblock response
    send_packet(unblocker['address'], msg)


def handle_check_online(username):
    """handles a check online request"""
    online_users = []
    for u_name in users:

        # skip self
        if u_name == username:
            continue

        u = users[u_name]

        # check whether user is blacklisted
        if username in u['blacklist']:
            continue

        # check if user is online
        if u['online_time']:
            online_users.append(u['username'])

    # send response
    user = users[username]
    online_users = ' '.join(online_users)
    msg = ' '.join((USERS_ONLINE, online_users))
    send_packet(user['address'], msg)


def handle_get_address_ask(target_name, asker_name):
    """handles a getaddress request"""
    asker = users[asker_name]

    # check for valid target
    if not (target_name in users):
        msg = ' '.join((GET_ADDR_INVALID, target_name))
        send_packet(asker['address'], msg)
        return

    target = users[target_name]
    # check whether address can be retrieved
    fail_msg = ' '.join((GET_ADDR_FAIL, target_name))
    if (asker_name in target['blacklist']) or (not target['online_time']):
        send_packet(asker['address'], fail_msg)
        return

    # extract address information
    asker_ip = asker['address'][0]
    asker_port = asker['address'][1]
    msg = ' '.join((GET_ADDR_ASK, asker_name, asker_ip, str(asker_port)))
    
    # P2P privacy: ask target for address
    send_packet(target['address'], msg)


def handle_get_address_ok(target_name, asker_name):
    """handles ok response from get address ask request"""
    asker = users[asker_name]
    target = users[target_name]
    if not (asker['online_time'] and asker['online_time']):
        return
    target_ip = target['address'][0]
    target_port = target['address'][1]
    msg = ' '.join((GET_ADDR_OK, target_name, target_ip, \
        str(target_port)))
    send_packet(asker['address'], msg)


def handle_get_address_fail(target_name, asker_name):
    """handles rejection of get address ask request"""
    asker = users[asker_name]
    if not asker['online_time']:
        return
    msg = ' '.join((GET_ADDR_FAIL, target_name))
    send_packet(asker['address'], msg)


def new_socket():
    """initialize a new socket"""
    return socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def is_blocked(user):
    """checks whether a user is blocked from logging in"""
    if user['block_time'] == 0: # offline
        return False 
    now = dt.datetime.now()
    if now-user['block_time'] < dt.timedelta(seconds=BLOCK_TIME):
        return True
    user['block_time'] = 0 #reset block
    return False


def send_offline_msgs(user):
    """sends all offline messages to be sent to a user"""
    offline_msgs = user['offline_msg_list']
    addr = user['address']
    
    # check for offline msgs queue
    if offline_msgs.empty():
        send_packet(addr, NO_OFFLINE_MSGS)
        return

    # send offline messages
    send_packet(addr, OFFLINE_MSGS_BEGIN)
    while not offline_msgs.empty():
        m = offline_msgs.get()
        msg = ' '.join((CHAT_MSG, m))
        send_packet(addr, msg)
    send_packet(addr, OFFLINE_MSGS_END)


def announce(username, log):
    """announces a user loggin in/out"""
    hero = users[username]
    for u_name in users:
        u = users[u_name]

        # skip self
        if u_name == username:
            continue

        # skip offline
        if not u['online_time']:
            continue

        # skip blacklisted
        if u_name in hero['blacklist']:
            continue

        # alert online friends of login/logout
        msg = ' '.join((log, username))
        send_packet(u['address'], msg)


def login_user(user, address):
    """login a user"""

    # check if already online
    if user['online_time']:
        send_packet(user['address'], LOGOUT_SAME_USER)
    
    # alert everyone of online status
    else: 
        announce(user['username'], ALERT_LOGIN)

    # initialize online status
    user['block_time'] = 0
    user['login_attempts'] = 0
    user['address'] = address
    user['online_time'] = dt.datetime.now()
    send_offline_msgs(user)


def logout_user(user):
    """logout a user"""
    user['address'] = None
    user['online_time'] = 0

    # announce logout
    announce(user['username'], ALERT_LOGOUT)


def main():
    """runs the chat server"""
    signal.signal(signal.SIGINT, sighandler)

    initialize_users(ACCOUNTS_FILENAME)

    # initialize listen socket
    listen_sock = new_socket()
    try:
        # use machine's IP address, and any available port
        listen_sock.bind(('0.0.0.0', 0))
        listen_sock.listen(5)
    except:
        print 'ERROR: could not initialize socket.'
        listen_sock.close()
        raise SystemExit

    # show IP address and port
    host_ip = socket.gethostbyname(socket.gethostname())
    host_port = listen_sock.getsockname()[1]
    print 'IP address: ', host_ip
    print 'Port: ', host_port 

    # check heartbeats
    hb_thread = Thread(target=check_heartbeat)
    hb_thread.setDaemon(True)
    hb_thread.start()

    # initialize worker threads
    thread_pool = []
    for i in range(THREAD_POOL_SIZE):
        receive_thread = Thread(target=process_incoming_packets)
        receive_thread.daemon = True
        receive_thread.start()

    # non-blocking accept
    input_socks = [listen_sock]
    while 1:
        read, write, error = select.select(input_socks, [], [])
        if error:
            listen_sock.close()
            print 'ERROR: socket select error.'
            break
        for sock in read:
            if sock == listen_sock:
                conn, addr = listen_sock.accept()
                socket_q.put(conn)

    # this should never be reached
    for sock in input_socks:
        sock.close()    
    raise SystemExit


if __name__ == '__main__':
    main()
