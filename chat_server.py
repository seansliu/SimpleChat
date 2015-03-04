import socket
import signal
import sys
from time import sleep
from threading import Thread
from Queue import Queue
from sets import Set
import datetime as dt
from configuration import *


users = {}              # all users
send_q = Queue()        # queue for all packets that need to be sent


def sighandler(signum, frame):
    """graceful exit"""
    print 'Shutting down server...\n'
    for username in users:
        user = users[username]
        if user['online_time']:
            try:
                end_sock = new_socket()
                end_sock.connect(user['address'])
                end_sock.send(SERVER_DOWN)
                end_sock.close()
            except:
                print 'ERROR: failed to notify %s of shutdown.' \
                %(send_address[0])
    print '------------------Simple Chat Server closed.--------------------\n'
    sys.exit(1)


def initialize_users(user_filename):
    """read userfile and initialize users dict"""
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
    user['address'] = None              # (ip_address, port)
    user['block_time'] = 0              # time when user was blocked
    user['offline_msg_list'] = Queue()  # list of strings: <sender> <msg>
    user['online_time'] = 0             # time when user last login/heartbeat
    user['blacklist'] = Set()   
    user['login_attempts'] = 0      
    return user


# thread
def send_packets():
    """sends packets through server_sock in an infinite loop"""
    while 1:
        send_contents = send_q.get()
        send_address = send_contents[0]
        packet = send_contents[1]

        try:
            server_sock = new_socket()
            server_sock.connect(send_address)
            server_sock.send(packet)
            server_sock.close()
        except:
            print 'ERROR: failed to send message to ', send_address


# thread
def check_heartbeat():
    '''checks whether each user is still online'''
    while 1: 
        for username in users:
            user = users[username]
            if not user['online_time']:
                continue
            now = dt.datetime.now()
            try:
                if now-user['online_time'] > dt.timedelta(seconds=TIMEOUT):
                    send_q.put((user['address'], LOGOUT_TIMED_OUT))
                    logout_user(user)
            except:
                continue


# thread
def process_incoming_packet(conn):
    """reads from client_sock and handles the request"""
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
        handle_get_address(target_name, asker_name)

    elif p_type == TURN_INVISIBLE:
        username = p_contents[1]
        #handle_invisible(username)

    elif p_type == TURN_VISIBLE:
        username = p_contents[1]
        #handle_visible(username)

    else:
        print 'ALERT: received unrecognized packet\n%s' %(packet)


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

    if password == user['password']:
        conn.send(LOGIN_OK)
        conn.close()
        login_user(user, user_addr)
        return

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
        send_q.put((user['address'], USER_BLOCKED))
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
    if not (receiver_name in users):
        msg = ' '.join((INVALID_RECEIVER, receiver_name))
        send_q.put((sender['address'], msg))
        return

    receiver = users[receiver_name]
    if sender_name in receiver['blacklist']:
        msg = ' '.join((MSG_BLOCKED, receiver_name))
        send_q.put((sender['address'], msg))
        return

    msg_contents = ' '.join((sender_name, msg_text))
    if not receiver['online_time']: 
        receiver['offline_msg_list'].put(msg_contents)
    else:
        msg = ' '.join((CHAT_MSG, msg_contents))
        send_q.put((receiver['address'], msg))
    ack = ' '.join((CHAT_MSG_OK, receiver_name))
    send_q.put((sender['address'], ack))


def handle_broadcast(sender_name, msg_text):
    """handles a broadcast request"""
    bcast_blocked = False

    for username in users:
        if username == sender_name:
            continue
        receiver = users[username]
        if sender_name in receiver['blacklist']:
            bcast_blocked = True
            continue

        msg_contents = ' '.join((sender_name, msg_text))
        if not receiver['online_time']: 
            receiver['offline_msg_list'].put(msg_contents)
        else:
            msg = ' '.join((CHAT_MSG, msg_contents))
            send_q.put((receiver['address'], msg))

    if bcast_blocked:
        sender = users[sender_name]
        send_q.put((sender['address'], BROADCAST_BLOCKED))
    else:
        send_q.put((sender['address'], BROADCAST_OK))


def handle_block(target_name, blocker_name):
    """handles a block request"""
    blocker = users[blocker_name]
    if not (target_name in users):
        msg = ' '.join((BLOCK_INVALID, target_name))
        send_q.put((blocker['address'], msg))
        return
    blocker['blacklist'].add(target_name)
    msg = ' '.join((BLOCK_OK, target_name))
    send_q.put((blocker['address'], msg))


def handle_unblock(target_name, unblocker_name):
    """handles an unblock request"""
    unblocker = users[unblocker_name]
    if not (target_name in unblocker['blacklist']):
        msg = ' '.join((UNBLOCK_INVALID, target_name))
        send_q.put((blocker['address'], msg))
        return
    unblocker['blacklist'].discard(target_name)
    msg = ' '.join((UNBLOCK_OK, target_name))
    send_q.put((unblocker['address'], msg))


def handle_check_online(username):
    """handles a check online request"""
    online_users = []
    for u_name in users:
        if u_name == username:
            continue
        u = users[u_name]
        if username in u['blacklist']:
            continue
        if u['online_time']:
            online_users.append(u['username'])
    user = users[username]
    online_users = ' '.join(online_users)
    msg = ' '.join((USERS_ONLINE, online_users))
    send_q.put((user['address'], msg))


def handle_get_address(target_name, asker_name):
    """handles a getaddress request"""
    asker = users[asker_name]
    if not (target_name in users):
        msg = ' '.join((GET_ADDR_INVALID, target_name))
        send_q.put((asker['address'], msg))
        return

    target = users[target_name]

    fail_msg = ' '.join((GET_ADDR_FAIL, target_name))
    if (asker_name in target['blacklist']) or (not target['online_time']):
        send_q.put((asker['address'], fail_msg))
        return

    target_ip = target['address'][0]
    target_port = target['address'][1]
    success_msg = ' '.join((GET_ADDR_OK, target_name, target_ip, \
        str(target_port)))
    asker_ip = asker['address'][0]
    asker_port = asker['address'][1]
    ask_msg = ' '.join((GET_ADDR_ASK, asker_name, asker_ip, str(asker_port)))
    
    try:
        getaddr_sock = new_socket()
        getaddr_sock.connect(target['address'])
        getaddr_sock.send(ask_msg)
        getaddr_response = getaddr_sock.recv(BUF_SIZE)
        getaddr_sock.close()
        if getaddr_response == GET_ADDR_OK:
            send_q.put((asker['address'], success_msg))
            return
    except:
        pass
    send_q.put((asker['address'], fail_msg))


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
         
    return False


def post_offline_msgs(user):
    """posts all offline messages to be sent to a user"""
    offline_msgs = user['offline_msg_list']
    addr = user['address']
    if offline_msgs.empty():
        send_q.put((addr, NO_OFFLINE_MSGS))
        return
    addr = user['address']
    send_q.put((addr, OFFLINE_MSGS_BEGIN))
    while not offline_msgs.empty():
        m = offline_msgs.get()
        msg = ' '.join((CHAT_MSG, m))
        send_q.put((addr, msg))
    send_q.put((addr, OFFLINE_MSGS_END))


def announce(username, log):
    """announces a user loggin in/out"""
    hero = users[username]
    for u_name in users:
        u = users[u_name]
        if u_name == username:
            continue
        if not u['online_time']:
            continue
        if u_name in hero['blacklist']:
            continue
        if username in u['blacklist']:
            continue
        msg = ' '.join((log, username))
        send_q.put((u['address'], msg))


def login_user(user, address):
    """login a user"""
    if user['online_time']:
        send_q.put((user['address'], LOGOUT_SAME_USER))
    else: 
        user['block_time'] = 0
        user['attempts'] = 0
        announce(user['username'], ALERT_LOGIN)
    user['address'] = address
    user['online_time'] = dt.datetime.now()
    post_offline_msgs(user)



def logout_user(user):
    """logout a user"""
    user['address'] = None
    user['online_time'] = 0
    announce(user['username'], ALERT_LOGOUT)


def main():
    """runs the chat server"""
    signal.signal(signal.SIGINT, sighandler)

    initialize_users(ACCOUNTS_FILENAME)

    # listen for incoming packets and process them
    listen_sock = new_socket()
    try:
        listen_sock.bind(('0.0.0.0', 0))
        listen_sock.listen(5)
    except:
        print 'ERROR: could not initialize socket.'
        raise SystemExit

    # show IP address and port
    host_ip = socket.gethostbyname(socket.gethostname())
    host_port = listen_sock.getsockname()[1]
    print 'IP address: ', host_ip
    print 'Port: ', host_port 

    # send packets
    send_thread = Thread(target=send_packets)
    send_thread.setDaemon(True)
    send_thread.start()

    # check heartbeats
    hb_thread = Thread(target=check_heartbeat)
    hb_thread.setDaemon(True)
    hb_thread.start()

    while 1:
        conn, addr = listen_sock.accept()
        receive_thread = Thread(target=process_incoming_packet, \
            args=(conn,))
        receive_thread.setDaemon(True)
        receive_thread.start()

    listen_sock.close()



if __name__ == '__main__':
    main()
