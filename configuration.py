BUF_SIZE = 4096
MAX_LOGIN_ATTEMPTS = 3
BLOCK_TIME = 60 #seconds
HEARTBEAT_TIME = 30 #seconds
TIMEOUT = 40 #seconds


ACCOUNTS_FILENAME = 'credentials.txt'

# requests from client to server
LOGIN = 'login'
LOGOUT = 'logout'
SEND_MSG = 'message'
PRIVATE_MSG = 'private'
BROADCAST= 'broadcast'
BLOCK_USER = 'block'
UNBLOCK_USER = 'unblock'
CHECK_ONLINE = 'online'
GET_ADDR = 'getaddress'
HELP = 'help'
CHECK_ADDRESS_BOOK = 'addressbook'
TURN_INVISIBLE = 'invisible' 	# extra credit
TURN_VISIBLE = 'visible'		# extra credit

# log responses from server to client
LOGIN_OK = 'login_ok'
ALREADY_OFFLINE = 'err_offline'
INVALID_PASSWORD = 'err_pword'
INVALID_USERNAME = 'err_uname'
LOGOUT_SAME_USER = 'logout_sameuser'
HEARTBEAT = 'heartbeat'

# message sending responses from server to client
INVALID_RECEIVER = 'err_rname'
CHAT_MSG_OK = 'chat_msg_ok'
BROADCAST_OK = 'bcast_ok'
MSG_BLOCKED = 'err_msgblocked'
BROADCAST_BLOCKED = 'err_bcastblocked'

# user blocking responses from server to client
BLOCK_OK = 'block_ok'
BLOCK_INVALID = 'err_blockuser'
UNBLOCK_OK = 'unblock_ok'
UNBLOCK_INVALID = 'err_unblockuser'

# get address response from server to client
GET_ADDR_OK = 'getaddr_ok'
GET_ADDR_FAIL = 'err_getaddrfail'
GET_ADDR_ASK = 'getaddr_ask'
GET_ADDR_INVALID = 'err_getaddruser'

# packet headers from server to client
CHAT_MSG = 'chat_msg'
ALERT_LOGIN = 'alert_login'
ALERT_LOGOUT = 'alert_logout'
USERS_ONLINE = 'users_online'
USER_BLOCKED = 'logout_blocked'
SERVER_DOWN = 'server_down'
LOGOUT_TIMED_OUT = 'logout_time'

# header and footer for offline messages from server to client
OFFLINE_MSGS_BEGIN = 'offline_msgs_begin'
OFFLINE_MSGS_END = 'offline_msgs_end'
NO_OFFLINE_MSGS = 'offline_none'

