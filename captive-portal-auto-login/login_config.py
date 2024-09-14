HANDLER_INIT_ARGS = {
    'source_address' : None
}
'''
Trick attribute to allow the urllib to bind a network interface

If source_address is a string the socket will try to bind to a network
interface based on its name

If source_address is a iterable object with ip_address and port, the socket
will try to bind to network interface based on them

Default value of source_address is None, and in this case the socket will
bind to network interface automatically
'''

# Patterns
SCRIPT_PATTERN_STRING = r"<script>\s*top\.self\.location\.href\s*=\s*'(.*?)'\s*<\/script>"
SUCCESS_PATTERN_STRING = r"http:\/\/(.*?)\/success\.jsp\?userIndex=(.*?)\s*"

# URL parts
BASE_URL = 'http://portal.whu.edu.cn:8080/'
'''Should endswith "/"'''
EPORTAL_URL = 'eportal/'
'''Should endswith "/"'''
INDEX_URL = 'index.jsp?'
FUNC_URL = 'InterFace.do?method='
LOGIN = 'login'
GET_STATUS = 'getOnlineUserInfo'
DEFAULT_METHOD = LOGIN

# Login attributes
USER_ID = ''
'''The account'''

PASSWORD = ''
'''
It is recommanded to use encrypted password

See login_bch.js:703 -> AuthInterface.js:148
'''

SERVICE = 'Internet'
'''Type of the operator
Only tested in value "Internet"'''

#The two fields seems not to be used
OP_ID = ''
OP_PWD = ''

DEFAULT_PASSWORD_ENCRYPTED = 'false'
'''Should be 'true' if the PASSWORD is encrypted'''

DEFAULT_HEADERS = [
    ('Content-Type', 'application/x-www-form-urlencoded; charset=UTF-8'),
]
# Detectors
DETECTOR_BASIC = 1
DETECTOR_GENERAL = 2
DETECTOR_CN = 4
DETECTOR_GLOBAL = 8
CONNETION_DETECTORS = DETECTOR_CN | DETECTOR_GENERAL | DETECTOR_BASIC
'''Used to detect if the network is available

Each detector implements a detect method and it returns
the status of network is connected or not'''

# Runtime configuration
ENCODING = 'utf-8'
LOGGING_LEVEL = 10
LOGGING_FORMAT = '%(asctime)s [%(levelname)s] %(message)s'
LOG_FILE = './login.log'
MAX_LOG_FILE_BYTES = 10**8
MAX_LOG_FILE_NUM = 5
TEST_INTERVAL = 600
FALLBACK_RETRY_INTERVAL = -1

DUMPED_IDENTIFIERS = globals().keys()

def add_attrs(obj, attrs, _dict):
    for i in attrs:
        if i.startswith('__'):
            continue
        setattr(obj, i, _dict[i])

class LoginConfig:
    def __init__(self, config_file=None):
        add_attrs(self, DUMPED_IDENTIFIERS, globals())
        if config_file is not None:
            import json
            with open(config_file, 'r') as f:
                attrs = json.load(f)
                add_attrs(self, attrs, attrs)