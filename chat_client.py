import socket
import select
import signal
import sys
from time import sleep
from threading import Thread
from thread import interrupt_main
from Queue import Queue
from configuration import *


session_info = {}       # important information for this session
address_book = {}       # maps usernames to addresses
send_q = Queue()        # queue for all packets that need to be sent
threads = []


def sighandler(signum, frame):
    """graceful exit"""
    print 'Shutting down client...'
    if 'username' in session_info:
        msg = ' '.join((LOGOUT, session_info['username']))
        try:
            end_sock = new_socket()
            end_sock.connect(session_info['server_addr'])
            end_sock.send(msg)
            end_sock.close()
        except:
            print 'ERROR: failed to inform server of logout.'
    print '\n-----------------Simple Chat Client closed.-------------------\n'
    sys.exit(1)


# thread
def post_heartbeats(hb_msg):
    """posts heartbeat messages to send_q every HEARTBEAT_TIME period"""
    while session_info['server_addr']:
        send_q.put((session_info['server_addr'], hb_msg))
        sleep(HEARTBEAT_TIME)


# thread
def process_commands():
    """manages the user's commands and puts them in the message queue"""
    username = session_info['username']
    server_addr = session_info['server_addr']
    host_ip = session_info['host_addr'][0]
    host_port = session_info['host_addr'][1]
    sleep(0.1)
    while 1:
        instructions = raw_input('').strip()
        command = instructions.split(' ', 2)

        if command[0] == SEND_MSG:
            if len(command) < 3:
                print 'Correct use: %s <target_user> <message>\n' %SEND_MSG
                continue
            packet = ' '.join((SEND_MSG, command[1], username, command[2]))
            if len(packet) > BUF_SIZE:
                print 'ERROR: message too long\n'
                continue
            send_q.put((server_addr, packet))

        elif command[0] == BROADCAST:
            if len(command) < 2:
                print 'Correct use: %s <message>\n' %BROADCAST
                continue
            command = instructions.split(' ', 1)
            packet = ' '.join((BROADCAST, username, command[1]))
            if len(packet) > BUF_SIZE:
                print 'ERROR: message too long\n'
                continue
            send_q.put((server_addr, packet))

        elif command[0] == CHECK_ONLINE:
            packet = ' '.join((CHECK_ONLINE, username))
            send_q.put((server_addr, packet))

        elif command[0] == BLOCK_USER:
            if len(command) < 2:
                print 'Correct use: %s <target_user>\n' %BLOCK_USER
                continue
            packet = ' '.join((BLOCK_USER, command[1], username))
            send_q.put((server_addr, packet))

        elif command[0] == UNBLOCK_USER:
            if len(command) < 2:
                print 'Correct use: %s <target_user>\n' %UNBLOCK_USER
                continue
            packet = ' '.join((UNBLOCK_USER, command[1], username))
            send_q.put((server_addr, packet))

        elif command[0] == GET_ADDR:
            if len(command) < 2:
                print 'Correct use: %s <target_user>\n' %GET_ADDR
                continue
            packet = ' '.join((GET_ADDR, command[1], username))
            send_q.put((server_addr, packet))

        elif command[0] == PRIVATE_MSG:
            if len(command) < 3:
                print 'Correct use: %s <user> <message>\n' %PRIVATE_MSG
                continue
            target_name = command[1]
            if not (target_name in address_book):
                print 'ERROR: could not private message user %s.\n' \
                %(target_name)
                continue
            packet = ' '.join((PRIVATE_MSG, username, command[2]))
            if len(packet) > BUF_SIZE:
                print 'ERROR: message too long.\n'
                continue
            send_q.put((address_book[target_name], packet))
            print 'Private message sent to user %s.\n' %target_name

        elif command[0] == LOGOUT:
            print 'Thank you for using Simple Chat. See you soon %s!\n' \
            %username
            packet = ' '.join((LOGOUT, username))
            send_q.put((server_addr, packet))
            interrupt_main()
            kill_sock = new_socket()
            kill_sock.connect(session_info['host_addr'])
            kill_sock.close()
            break

        elif command[0] == HELP:
            commands = '\n'.join(('List of commands:', SEND_MSG, BROADCAST, \
                CHECK_ONLINE, BLOCK_USER, UNBLOCK_USER, GET_ADDR, \
                CHECK_ADDRESS_BOOK, PRIVATE_MSG, TURN_INVISIBLE, TURN_VISIBLE, \
                LOGOUT, '\n'))
            print commands

        elif command[0] == '':
            pass

        elif command[0] == CHECK_ADDRESS_BOOK:
            if address_book:
                print 'Users in your Address Book:'
                for username in address_book:
                    print username
            else:
                print 'Your Address Book is empty.\n'

        # extra credit invisibility
        elif command[0] == TURN_INVISIBLE:
            pass
        elif command[0] == TURN_VISIBLE:
            pass

        else:
            print 'Invalid command. Type \'%s\' for a list of commands.\n' \
            %HELP


# thread
def send_packets():
    """sends packets through server_sock in an endless loop"""
    while 1:
        if send_q.empty():
            continue
        send_contents = send_q.get()
        send_address = send_contents[0]
        packet = send_contents[1]

        try:
            server_sock = new_socket()
            server_sock.connect(send_address)
            server_sock.send(packet)
            server_sock.close()
        except:
            print 'ERROR: failed to send message to IP %s.\n' %send_address[0]


def process_incoming_packet(conn):
    """handles incoming packets"""
    packet = conn.recv(BUF_SIZE)
    p_contents = packet.split(' ', 1)
    p_type = p_contents[0]

    if p_type == GET_ADDR_ASK:
        contents = p_contents[1].split(' ', 2)
        handle_get_addr_ask(contents[0], contents[1], int(contents[2]), conn)
        return

    conn.close()

    if p_type == INVALID_RECEIVER:
        handle_invalid_receiver(p_contents[1])

    elif p_type == MSG_BLOCKED:
        handle_msg_blocked(p_contents[1])

    elif p_type == BROADCAST_BLOCKED:
        handle_broadcast_blocked()

    elif p_type == CHAT_MSG_OK:
        handle_chat_msg_ok(p_contents[1])

    elif p_type == BROADCAST_OK:
        handle_broadcast_ok()

    elif p_type == BLOCK_OK:
        handle_block_ok(p_contents[1])

    elif p_type == BLOCK_INVALID:
        handle_block_invalid(p_contents[1])

    elif p_type == UNBLOCK_OK:
        handle_unblock_ok(p_contents[1])

    elif p_type == UNBLOCK_INVALID:
        handle_unblock_invalid(p_contents[1])

    elif p_type == GET_ADDR_OK:
        contents = p_contents[1].split(' ', 2)
        handle_get_addr_ok(contents[0], contents[1], int(contents[2]))

    elif p_type == GET_ADDR_FAIL:
        handle_get_addr_fail(p_contents[1])

    elif p_type == GET_ADDR_INVALID:
        handle_get_addr_invalid(p_contents[1])

    elif p_type == CHAT_MSG:
        contents = p_contents[1].split(' ', 1)
        handle_chat_msg(contents[0], contents[1])

    elif p_type == PRIVATE_MSG:
        contents = p_contents[1].split(' ', 1)
        sender_name = contents[0]
        msg_text = contents[1]
        handle_private_msg(sender_name, msg_text)

    elif p_type == ALERT_LOGIN:
        handle_alert_login(p_contents[1])

    elif p_type == ALERT_LOGOUT:
        handle_alert_logout(p_contents[1])

    elif p_type == USERS_ONLINE:
        handle_users_online(p_contents[1])

    elif p_type == OFFLINE_MSGS_BEGIN:
        handle_offline_msgs_begin()

    elif p_type == OFFLINE_MSGS_END:
        handle_offline_msgs_end()

    elif p_type == NO_OFFLINE_MSGS:
        handle_no_offline_msgs()

    elif p_type == LOGOUT_SAME_USER:
        handle_logout_same_user()

    elif p_type == USER_BLOCKED:
        handle_logout_blocked()

    elif p_type == SERVER_DOWN:
        handle_server_down()

    elif p_type == LOGOUT_TIMED_OUT:
        handle_logout_timed_out()

    else:
        print 'ALERT: unknown message received.\n'
        interrupt_main()
    return


def handle_invalid_receiver(username):
    print 'ERROR: message receiver %s not found.\n' %username


def handle_msg_blocked(username):
    print 'ERROR: user %s has blocked you.\n' %username


def handle_broadcast_blocked():
    print '> Your broadcast could not be delivered to some recipients.\n'


def handle_chat_msg_ok(username):
    print '> Your message was sent to user %s.\n' %username


def handle_broadcast_ok():
    print '> Your broadcast was sent to all users.\n'


def handle_block_ok(username):
    print '> User %s has been blocked.\n' %username


def handle_block_invalid(username):
    print 'ERROR: block target %s not found.\n' %username


def handle_unblock_ok(username):
    print '> User %s has been unblocked.\n' %username


def handle_unblock_invalid(username):
    print 'ERROR: invalid unblock target %s.\n' %username


def handle_get_addr_ok(username, target_ip, target_port):
    address_book[username] = (target_ip, target_port)
    print 'Address of user %s saved.\n' %username

def handle_get_addr_ask(username, asker_ip, asker_port, conn):
    print 'User %s is asking to exchange private messages with you. \
    Press [enter] to continue.' %username
    response = raw_input('Would you like to accept? [Y/n] ')
    if response.lower()[0] == 'y':
        address_book[username] = (asker_ip, asker_port)
        print 'Address of user %s saved.\n' %username
        conn.send(GET_ADDR_OK)
    else:
        conn.send(GET_ADDR_FAIL)


def handle_get_addr_fail(username):
    print 'ERROR: failed to retrieve address of user %s.\n' %username


def handle_get_addr_invalid(username):
    print 'ERROR: address retrieval user %s does not exist.\n' %username


def handle_chat_msg(username, msg_text):
    print '%s: %s\n' %(username, msg_text)


def handle_private_msg(username, msg_text):
    if not (username in address_book):
        print 'WARNING: message received from unknown sender\n.'
        interrupt_main()
    print '[private] %s: %s\n' %(username, msg_text)


def handle_alert_login(username):
    print '> User %s has logged in.\n' %username


def handle_alert_logout(username):
    if username in address_book:
        del address_book[username]
    print '> User %s has logged out.\n' %username


def handle_users_online(usernames):
    if usernames == '':
        print '> No other uses online.\n'
        return
    output = usernames.replace(' ', '\n>> ')
    print '> Online users:\n>> %s\n' %output


def handle_offline_msgs_begin():
    print '>>> Here are the messages you missed while offline:\n'


def handle_offline_msgs_end():
    print '>>> End of offline messages.\n\n'


def handle_no_offline_msgs():
    print '>>> No messages received while offline.\n'


def handle_logout_same_user():
    print '> Another client has logged into your account. You have been \
    logged out.\n'
    del session_info['username']
    interrupt_main()


def handle_logout_blocked():
    print '> Due to multiple login attempts from another client, your \
    account is now blocked.\n'
    interrupt_main()


def handle_server_down():
    print '> Simple Chat server is down.\n'
    if not address_book:
        interrupt_main()
    else:
        session_info['server_addr'] = None
        print '> You may still privately chat with users.\n'


def handle_logout_timed_out():
    print '> Due to heartbeat timeout, you have been logged out.\n'
    interrupt_main()


def check_commandline(how_many):
    """Checks the command line"""
    args = len(sys.argv)
    if args != how_many:
        print 'correct use: python client.py <ip address> <port>'
        sys.exit()


def new_socket():
    """initialize a new socket"""
    return socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def login():
    """Manages user login"""
    server_addr = session_info['server_addr']
    host_addr = session_info['host_addr']
    username = raw_input('Username: ')

    while 1:
        password = raw_input('Password: ')
        login_packet = ' '.join((LOGIN, username, password, \
            session_info['host_addr'][0], str(session_info['host_addr'][1])))

        try:
            login_sock = new_socket()
            login_sock.connect(server_addr)
            login_sock.send(login_packet)
            login_response = login_sock.recv(BUF_SIZE)
            login_sock.close()
        except:
            print 'ERROR: failed to connect to chat server.\n'
            return False

        if login_response == LOGIN_OK:
            session_info['username'] = username
            print ''
            return True

        if login_response == INVALID_PASSWORD:
            print '> Invalid password. Please try again.\n'
            continue # let user try again

        if login_response == INVALID_USERNAME:
            print '> Invalid Username.'
        elif login_response == USER_BLOCKED:
            print '> This user is currently blocked. Please try again later.\
            \n'
        else:
            print '> Unknown login error.\n'
        break
    return False


def main():
    '''runs the chat client'''
    signal.signal(signal.SIGINT, sighandler)

    check_commandline(3)
    print '> Starting Simple Chat client...'
    session_info['server_addr'] = (sys.argv[1], int(sys.argv[2]))

    # listen for incoming packets and process them
    listen_sock = new_socket()
    #listen_sock.setblocking(0)
    try:
        listen_sock.bind(('0.0.0.0', 0))
        listen_sock.listen(5)

    except:
        print 'ERROR: could not initialize socket.\n'
        raise SystemExit

    host_ip = socket.gethostbyname(socket.gethostname())
    host_port = listen_sock.getsockname()[1]
    session_info['host_addr'] = (host_ip, host_port)

    login_result = login()
    if not login_result:
        raise SystemExit

    # start sending packets
    send_thread = Thread(target=send_packets)
    send_thread.daemon = True
    send_thread.start()

    # send heartbeats
    hb_msg = ' '.join((HEARTBEAT, session_info['username']))
    hb_thread = Thread(target=post_heartbeats, args=(hb_msg,))
    hb_thread.daemon = True
    hb_thread.start()

    # print welcome
    print '----------------------------------------------------------------\n'
    print 'Welcome to Simple Chat, %s!\n' %session_info['username']
    print '----------------------------------------------------------------\n'

    # read and process user commands
    commands_thread = Thread(target=process_commands)
    commands_thread.daemon = True
    commands_thread.start()

    inputs = [listen_sock]

    # non-blocking accept
    while 1:
        read, write, error = select.select(inputs, [], [])
        for sock in read:
            if sock == listen_sock:
                conn, addr = listen_sock.accept()
                inputs.append(conn)
            else:
                process_incoming_packet(sock)
                inputs.remove(sock)
    listen_sock.close()


if __name__ == '__main__':
   main()
