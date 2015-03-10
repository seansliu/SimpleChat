# SimpleChat Configurations
#
# Written by Sean Liu


MAX_LOGIN_ATTEMPTS = 3
BLOCK_TIME = 60 #seconds
HEARTBEAT_TIME = 30 #seconds
TIMEOUT = HEARTBEAT_TIME + 5 #seconds, give a little leeway
THREAD_POOL_SIZE = 16
BUF_SIZE = 4096
ACCOUNTS_FILENAME = 'credentials.txt'

# user commands on client
LOGIN = 'login'
LOGOUT = 'logout'
SEND_MSG = 'message'
PRIVATE_MSG = 'private'
BROADCAST= 'broadcast'
BLOCK_USER = 'block'
UNBLOCK_USER = 'unblock'
CHECK_ONLINE = 'online'
GET_ADDR = 'getaddress'
REMOVE_ADDR = 'removeaddress'
CHECK_ADDRESS_BOOK = 'addressbook'
HELP = 'help'

# upcoming features
# GET_STATUS = 'status'
# SET_INVISIBLE = 'invisible'
# SET_BUSY = 'busy'
# SET_AVAILABLE = 'available'


# --- Protocol ---
#
# log responses from server to client
LOGIN_OK = 'login0'
INVALID_PASSWORD = 'login1'
INVALID_USERNAME = 'login2'
LOGOUT_SAME_USER = 'logout1'
HEARTBEAT = 'hbeat'

# message sending responses from server to client
CHAT_MSG_OK = 'msg0'
INVALID_RECEIVER = 'msg1'
MSG_BLOCKED = 'msg2'
BROADCAST_OK = 'bcast0'
BROADCAST_BLOCKED = 'bcast1'

# user blocking responses from server to client
BLOCK_OK = 'block0'
BLOCK_INVALID = 'block1'
ALREADY_BLOCKED = 'block2'
UNBLOCK_OK = 'unblock0'
UNBLOCK_INVALID = 'unblock1'

# 'getaddress' response from server to client
GET_ADDR_OK = 'getaddr0'
GET_ADDR_INVALID = 'getaddr1'
GET_ADDR_FAIL = 'getaddr2'
GET_ADDR_ASK = 'getaddr3'

# packet headers from server to client
CHAT_MSG = 'chat_msg'
ALERT_LOGIN = 'alert0'
ALERT_LOGOUT = 'alert1'
USERS_ONLINE = 'on_users'
USER_BLOCKED = 'boot0'
LOGOUT_TIMED_OUT = 'boot1'
SERVER_DOWN = 'boot2'

# header and footer for offline messages from server to client
OFFLINE_MSG_OK = 'off_msg0'
OFFLINE_MSGS_BEGIN = 'off_msg1'
OFFLINE_MSGS_END = 'off_msg2'
NO_OFFLINE_MSGS = 'off_msg3'

