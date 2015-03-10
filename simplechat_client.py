# SimpleChat Client
# 
# Written by Sean Liu


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


def sighandler(signum, frame):
    """graceful exit"""
    print 'Shutting down SimpleChat Client...'

    # close listening socket
    if 'listen_sock' in session_info:
        session_info['listen_sock'].close()

    if 'username' in session_info:
        # notify server of logout
        msg = ' '.join((LOGOUT, session_info['username']))
        try:
            end_sock = new_socket()
            end_sock.connect(session_info['server_addr'])
            end_sock.send(msg)
            end_sock.close()
            address_book.clear() # server will notify peers
        except:
           print 'ERROR: failed to inform SimpleChat Server of logout.'

        # notify peers of logout 
        msg = ' '.join((ALERT_LOGOUT, session_info['username']))
        for username in address_book:
            try:
                end_sock = new_socket()
                end_sock.connect(address_book[username])
                end_sock.send(msg)
                end_sock.close()
            except:
               print 'ERROR: failed to inform user %s of logout.' %username

    print '\n-----------------SimpleChat Client closed.-------------------\n'
    sys.exit(1)


# thread
def send_heartbeats(hb_msg):
    """sends heartbeat messages to server every HEARTBEAT_TIME period"""
    while session_info['server_addr']:
        send_packet(session_info['server_addr'], hb_msg)
        sleep(HEARTBEAT_TIME)


# thread
def process_commands():
    """manages the user's commands and puts them in the message queue"""
    username = session_info['username']
    server_addr = session_info['server_addr']
    host_ip = session_info['host_addr'][0]
    host_port = session_info['host_addr'][1]
    input_fd = [sys.stdin]

    while 1:
        # non-blocking reading from stdin
        read, write, error = select.select(input_fd, [], [])
        if not (sys.stdin in read):
            continue

        user_input = sys.stdin.readline().strip()
        command = user_input.split(' ', 2)

        # send normal chat message
        if command[0] == SEND_MSG:
            if len(command) < 3:
                print '> Correct use: %s <user> <message>\n' %SEND_MSG
                continue
            if command[1] == session_info['username']:
                print '> ERROR: cannot message yourself.\n'
                continue
            packet = ' '.join((SEND_MSG, command[1], username, command[2]))
            if len(packet) > BUF_SIZE:
                print '> ALERT: message too long - truncated.'
            send_packet(server_addr, packet[:BUF_SIZE])

        # broadcast message
        elif command[0] == BROADCAST:
            if len(command) < 2:
                print '> Correct use: %s <message>\n' %BROADCAST
                continue
            command = user_input.split(' ', 1)
            packet = ' '.join((BROADCAST, username, command[1]))
            if len(packet) > BUF_SIZE:
                print '> ALERT: broadcast message too long - truncated.'
            send_packet(server_addr, packet[:BUF_SIZE])

        # check who else is online
        elif command[0] == CHECK_ONLINE:
            packet = ' '.join((CHECK_ONLINE, username))
            send_packet(server_addr, packet)

        # blocking a user
        elif command[0] == BLOCK_USER:
            if len(command) < 2:
                print '> Correct use: %s <user>\n' %BLOCK_USER
                continue
            packet = ' '.join((BLOCK_USER, command[1], username))
            send_packet(server_addr, packet)

        # unblocking a user
        elif command[0] == UNBLOCK_USER:
            if len(command) < 2:
                print '> Correct use: %s <user>\n' %UNBLOCK_USER
                continue
            packet = ' '.join((UNBLOCK_USER, command[1], username))
            send_packet(server_addr, packet)

        # get user address for private messaging
        elif command[0] == GET_ADDR:
            if len(command) < 2:
                print '> Correct use: %s <user>\n' %GET_ADDR
                continue
            if command[1] == session_info['username']:
                print '> ERROR: ask for someone else\'s address.\n'
                continue
            packet = ' '.join((GET_ADDR, command[1], username))
            send_packet(server_addr, packet)

        # remove user address, no more private messaging each other
        elif command[0] == REMOVE_ADDR:
            if len(command) < 2:
                print '> Correct use: %s <user>\n' %REMOVE_ADDR
                continue            
            if not (command[1] in address_book):
                print '> ERROR: user %s is not in your Address Book.\n' \
                %command[1]
                continue
            packet = ' '.join((REMOVE_ADDR, username))
            send_packet(address_book[command[1]], packet)
            del address_book[command[1]]
            print '> User %s removed from Address Book.\n' %command[1]

        # send private chat message
        elif command[0] == PRIVATE_MSG:
            if len(command) < 3:
                print '> Correct use: %s <user> <message>\n' %PRIVATE_MSG
                continue
            target_name = command[1]
            if not (target_name in address_book):
                print '> ERROR: could not privately message user %s.\n' \
                %(target_name)
                continue
            packet = ' '.join((PRIVATE_MSG, username, command[2]))
            if len(packet) > BUF_SIZE:
                print '> ALERT: your message was truncated.'
            send_packet(address_book[target_name], packet[:BUF_SIZE])
            print '> Private message sent to user %s.\n' %target_name

        # log out
        elif command[0] == LOGOUT:
            print '> Thank you for using Simple Chat. See you soon, %s!\n' \
            %username
            interrupt_main()
            
            # interrupt accept
            kill_sock = new_socket()
            kill_sock.connect(session_info['host_addr'])
            kill_sock.close()
            break

        # check who is available for private messaging
        elif command[0] == CHECK_ADDRESS_BOOK:
            if address_book:
                print '> Your Address Book (available for private messaging):'
                for u_name in address_book:
                    print '>> %s' %u_name
                print ''
            else:
                print '> Your Address Book is empty.\n'

        # help - list out all commands
        elif command[0] == HELP:
            commands = '\n>> '.join(('> Commands:', SEND_MSG, BROADCAST, \
                CHECK_ONLINE, BLOCK_USER, UNBLOCK_USER, GET_ADDR, \
                REMOVE_ADDR, CHECK_ADDRESS_BOOK, PRIVATE_MSG, LOGOUT))
            print '%s\n' %commands

        # allow user to make space
        elif command[0] == '':
            pass

        # unrecognized command
        else:
            print '> ERROR: invalid command. ' + \
            'Type \'%s\' for a list of available commands.\n' %HELP


def send_packet(send_address, packet):
    """sends packet to send_address"""
    try:
        send_sock = new_socket()
        send_sock.connect(send_address)
        send_sock.send(packet)
        send_sock.close()
    except:
         print '> ERROR: failed to send message to IP %s.\n>> %s\n' \
        %(send_address[0], packet)


def process_incoming_packet(conn):
    """handles incoming packets"""
    # read conn socket and split results
    packet = conn.recv(BUF_SIZE)
    conn.close()
    p_contents = packet.split(' ', 1)
    p_type = p_contents[0]

    if p_type == INVALID_RECEIVER:
        handle_invalid_receiver(p_contents[1])

    elif p_type == MSG_BLOCKED:
        handle_msg_blocked(p_contents[1])

    elif p_type == BROADCAST_BLOCKED:
        handle_broadcast_blocked()

    elif p_type == CHAT_MSG_OK:
        handle_chat_msg_ok(p_contents[1])

    elif p_type == OFFLINE_MSG_OK:
        handle_offline_msg_ok(p_contents[1])

    elif p_type == BROADCAST_OK:
        handle_broadcast_ok()

    elif p_type == BLOCK_OK:
        handle_block_ok(p_contents[1])

    elif p_type == ALREADY_BLOCKED:
        handle_already_blocked(p_contents[1])

    elif p_type == BLOCK_INVALID:
        handle_block_invalid(p_contents[1])

    elif p_type == UNBLOCK_OK:
        handle_unblock_ok(p_contents[1])

    elif p_type == UNBLOCK_INVALID:
        handle_unblock_invalid(p_contents[1])

    elif p_type == GET_ADDR_ASK:
        contents = p_contents[1].split(' ', 2)
        handle_get_addr_ask(contents[0], contents[1], int(contents[2]))

    elif p_type == GET_ADDR_OK:
        contents = p_contents[1].split(' ', 2)
        handle_get_addr_ok(contents[0], contents[1], int(contents[2]))

    elif p_type == GET_ADDR_FAIL:
        handle_get_addr_fail(p_contents[1])

    elif p_type == GET_ADDR_INVALID:
        handle_get_addr_invalid(p_contents[1])

    elif p_type == REMOVE_ADDR:
        handle_remove_addr(p_contents[1])

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
        print '> ALERT: unknown message received.\n%s\n' %packet
        interrupt_main()


def handle_invalid_receiver(username):
    print '> ERROR: message receiver %s not found.\n' %username


def handle_msg_blocked(username):
    print '> ERROR: user %s has blocked you - could not send message.\n' \
    %username


def handle_broadcast_blocked():
    print '> Your broadcast could not be delivered to some recipients.\n'


def handle_chat_msg_ok(username):
    print '> Your message was sent to user %s.\n' %username


def handle_offline_msg_ok(username):
    print '> Your offline message was sent to user %s.\n' %username


def handle_broadcast_ok():
    print '> Your broadcast was sent to all online users.\n'


def handle_block_ok(username):
    print '> User %s has been blocked.\n' %username


def handle_already_blocked(username):
    print '> ERROR: user %s is already blocked.\n' %username


def handle_block_invalid(username):
    print '> ERROR: invalid block target user %s.\n' %username


def handle_unblock_ok(username):
    print '> User %s has been unblocked.\n' %username


def handle_unblock_invalid(username):
    print '> ERROR: invalid unblock target user %s.\n' %username


# P2P security and consent
def handle_get_addr_ok(username, target_ip, target_port):
    address_book[username] = (target_ip, target_port)
    print '> Address of user %s saved.\n' %username


# P2P security and consent
def handle_get_addr_ask(username, asker_ip, asker_port):
    print '> ALERT: User %s wants to exchange private messages with you. ' \
    %username
    response = raw_input('> Would you like to accept? [Y/n] ')
    if len(response) == 0 or response.lower()[0] != 'y':
        print '>> Address not given to user %s.\n' %username
        msg = ' '.join((GET_ADDR_FAIL, username, session_info['username']))
    else:
        address_book[username] = (asker_ip, asker_port)
        print '>> Address of user %s saved.\n' %username
        msg = ' '.join((GET_ADDR_OK, username, session_info['username']))
    send_packet(session_info['server_addr'], msg)


def handle_get_addr_fail(username):
    print '> ERROR: failed to retrieve address of user %s.\n' %username


def handle_get_addr_invalid(username):
    print '> ERROR: user %s does not exist.\n' %username


def handle_remove_addr(username):
    if username in address_book:
        del address_book[username]
        print '> ALERT: user %s has been removed from Address Book.\n' \
        %username


def handle_chat_msg(username, msg_text):
    print '%s: %s\n' %(username, msg_text)


def handle_private_msg(username, msg_text):
    print '[private] %s: %s\n' %(username, msg_text)
    if not (username in address_book):
        print '> ALERT: message received from unknown sender.\n'
        interrupt_main()
        

def handle_alert_login(username):
    print '> User %s has logged in.\n' %username


def handle_alert_logout(username):
    print '> User %s has logged out.\n' %username
    if username in address_book:
        del address_book[username]


def handle_users_online(usernames):
    if usernames == '':
        print '> No other uses online.\n'
        return
    output = usernames.replace(' ', '\n>> ')
    print '> Online users:\n>> %s\n' %output


def handle_offline_msgs_begin():
    print '>>> Here are the messages you missed while offline:\n'


def handle_offline_msgs_end():
    print '>>> End of offline messages.\n'


def handle_no_offline_msgs():
    print '>>> No messages received while offline.\n'


def handle_logout_same_user():
    print '> ALERT: another client has logged into your account, ' + \
    'you have been logged out.\n'
    del session_info['username']
    interrupt_main()


def handle_logout_blocked():
    print '> ALERT: due to multiple login attempts from another client, ' + \
    'your account is now blocked.\n'
    del session_info['username']
    interrupt_main()


def handle_server_down():
    print '> ALERT: Simple Chat server is down.\n'
    session_info['server_addr'] = None
    if not address_book:
        interrupt_main()
    else:
        print '> You may still privately chat with users.\n'


def handle_logout_timed_out():
    print '> ALERT: due to heartbeat timeout, you have been logged out.\n'
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
    """manages user login"""
    server_addr = session_info['server_addr']
    host_addr = session_info['host_addr']
    username = raw_input('Username: ').strip()

    while 1:
        password = raw_input('Password: ')
        login_packet = ' '.join((LOGIN, username, password, \
            session_info['host_addr'][0], str(session_info['host_addr'][1])))

        # send login request and receive response
        try:
            login_sock = new_socket()
            login_sock.connect(server_addr)
            login_sock.send(login_packet)
            login_response = login_sock.recv(BUF_SIZE)
            login_sock.close()
        except:
            print 'ERROR: failed to connect to chat server.\n'
            return False

        # successful login
        if login_response == LOGIN_OK:
            session_info['username'] = username
            return True

        # bad password
        if login_response == INVALID_PASSWORD:
            print '> Invalid password. Please try again.\n'
            continue # let user try again until server says stop

        # bad login request
        if login_response == INVALID_USERNAME:
            print '> Invalid Username.\n'
        elif login_response == USER_BLOCKED:
            print '> This user is currently blocked. Please try again later.'
            print ''
        else:
            print '> Unknown login error. \n'
        return False


def main():
    '''runs the chat client'''
    signal.signal(signal.SIGINT, sighandler)
    check_commandline(3)

    print '> Starting Simple Chat client...'

    # check and save server address
    try:
        session_info['server_addr'] = (sys.argv[1], int(sys.argv[2]))
    except:
        print '> ERROR: invalid IP address and/or port number'
        raise SystemExit

    # initialize listen socket
    listen_sock = new_socket()
    try:
        # use machine's IP address, and any available port
        listen_sock.bind(('0.0.0.0', 0))
        listen_sock.listen(10)
    except:
        print '> ERROR: could not initialize socket.\n'
        raise SystemExit

    # save host address
    host_ip = socket.gethostbyname(socket.gethostname())
    host_port = listen_sock.getsockname()[1]
    print '> Initializing on IP address %s and port %d ...' \
    %(host_ip, host_port)
    session_info['host_addr'] = (host_ip, host_port)

    # attempt login
    login_result = login()
    if not login_result:
        raise SystemExit

    # print welcome
    print ''
    print '----------------------------------------------------------------\n'
    print 'Welcome to SimpleChat, %s!\n' %session_info['username']
    print '----------------------------------------------------------------\n'

    # send heartbeats
    hb_msg = ' '.join((HEARTBEAT, session_info['username']))
    hb_thread = Thread(target=send_heartbeats, args=(hb_msg,))
    hb_thread.daemon = True
    hb_thread.start()

    # read and process user commands
    commands_thread = Thread(target=process_commands)
    commands_thread.daemon = True
    commands_thread.start()

    input_socks = [listen_sock]
    session_info['listen_sock'] = listen_sock

    # non-blocking accept
    while 1:
        read, write, error = select.select(input_socks, [], [])
        if error:
            print 'ERROR: socket select error.'
            break
        for sock in read:
            if sock == listen_sock:
                conn, addr = listen_sock.accept()
                input_socks.append(conn)
            else:
                process_incoming_packet(sock)
                input_socks.remove(sock)

    # this should never be reached
    for sock in input_socks:
        sock.close()
    raise SystemExit


if __name__ == '__main__':
   main()
