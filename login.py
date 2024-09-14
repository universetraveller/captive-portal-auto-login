import json
import logging.handlers
import sys
import time
import urllib.request
import handlers
import re
import login_config
import urllib.parse
import detectors
import logging
import traceback
import socket
import os
import ast
import argparse
import crypt_utils
import hashlib
import commands

_global_config = login_config
'''Context to run a daemon'''

def install_config(config):
    '''
    This function can be called at runtime and set a new context for the module
    '''
    global _global_config
    _global_config = config

def build_opener():
    '''
    This function returns a opener that can be use as common urllib
    Usage:
        urllib.urlopen -> opener.open
    '''
    return urllib.request.build_opener(*handlers.get_handlers())

def init_opener():
    '''
    Install the default opener so that urllib.urlopen can call
    correct opener.open method
    '''
    urllib.request.install_opener(build_opener())

_script_pattern = None
_detector = None
def init_script_parser():
    global _script_pattern
    global _detector
    _script_pattern = re.compile(_global_config.SCRIPT_PATTERN_STRING)
    _detector = detectors.URLDetector(f'{_global_config.BASE_URL}',
                                      re.compile(_global_config.SUCCESS_PATTERN_STRING),
                                      encoding='latin-1')

def get_post_data(query_string, encoding=None):
    data = {
        'userId' : _global_config.USER_ID,
        'password' : _global_config.PASSWORD,
        'service' : _global_config.SERVICE,
        'queryString' : query_string,
        'operatorPwd' : _global_config.OP_PWD,
        'operatorUserId' : _global_config.OP_ID,
        'validcode' : '',
        'passwordEncrypt' : _global_config.DEFAULT_PASSWORD_ENCRYPTED
    }
    if encoding is None:
        return data
    return urllib.parse.urlencode(data).encode(encoding)

def add_default_headers(request: urllib.request.Request):
    for header in _global_config.DEFAULT_HEADERS:
        request.add_header(header[0], header[1])

_detectors = []
def init_detectors():
    global _detectors
    # avoid initializing repeatedly
    _detectors = []
    if _global_config.CONNETION_DETECTORS & _global_config.DETECTOR_CN:
        _detectors.extend(detectors.DETECTORS_CN)
    if _global_config.CONNETION_DETECTORS & _global_config.DETECTOR_GENERAL:
        _detectors.extend(detectors.DETECTORS_GENERAL)
    if _global_config.CONNETION_DETECTORS & _global_config.DETECTOR_GLOBAL:
        _detectors.extend(detectors.DETECTORS_GLOBAL)
    if _global_config.CONNETION_DETECTORS & _global_config.DETECTOR_BASIC:
        _detectors.append(_detector)
    # ensure detectors are not empty
    assert _detectors

_logger = None
def init_logger():
    global _logger
    _logger = None
    logging.basicConfig(level=_global_config.LOGGING_LEVEL,
                        format=_global_config.LOGGING_FORMAT)
    _logger = logging.getLogger('LoginLogger')
    _logger.setLevel(_global_config.LOGGING_LEVEL)
    file_handler = logging.handlers.RotatingFileHandler(_global_config.LOG_FILE,
                                                        maxBytes=_global_config.MAX_LOG_FILE_BYTES,
                                                        backupCount=_global_config.MAX_LOG_FILE_NUM)
    file_handler.setLevel(_global_config.LOGGING_LEVEL)
    formatter = logging.Formatter(_global_config.LOGGING_FORMAT)
    file_handler.setFormatter(formatter)
    _logger.addHandler(file_handler)
    _logger.debug('The logger is initialized')

_index_url = None
_request_url = None
def init_pages():
    global _index_url
    global _request_url
    _index_url = f'{_global_config.BASE_URL}{_global_config.EPORTAL_URL}{_global_config.INDEX_URL}'
    _request_url = f'{_global_config.BASE_URL}{_global_config.EPORTAL_URL}{_global_config.FUNC_URL}{_global_config.LOGIN}'

_INIT_END = False
def init():
    '''
    Initialize components based on a context
    When the context is updated, we usually should
    call init() manually to make the new configuration
    take effect
    '''
    global _INIT_END
    _INIT_END = False
    init_logger()
    init_opener()
    _logger.debug('Opener initialized')
    init_script_parser()
    _logger.debug('Script parser initialized')
    init_detectors()
    _logger.debug('Detectors initialized')
    init_pages()
    _logger.debug('Pages initialized')
    _logger.info(f'Basic components are initialized')
    _INIT_END = True

def detect_connected():
    '''
    This function is used to check if the network
    is available
    '''
    for detector in _detectors:
        try:
            if detector.detect():
                return True
        except Exception as e:
            _logger.warning(f'Skip {detector} because it is broken')
            _logger.info(f'Reason: {e}\n{traceback.format_exc()}')
            continue
    return False

def collect_redirect_urls():
    redirect_set = set()
    for detector in _detectors:
        redirect_set.add(detector.get_last_redirect().strip())
        detector.reset_history()
    return redirect_set

def login():
    '''
    This function assume we have tested that there is no
    network available so that redirected urls are stored in
    the detectors and we can collect them
    '''
    urls = collect_redirect_urls()
    if not urls:
        _logger.info('Collect no urls; Exit process')
        return False
    if len(urls) > 1:
        _logger.warning(f'{len(urls)} redirected urls were collected (expected 1)')
        _logger.debug(f'URLs:\n{urls}')
    url = urls.pop()
    _logger.debug(f'Used redirected url: {url}')
    query_strings = _script_pattern.findall(url)
    if not query_strings:
        _logger.error('Could not parse query string from the url')
        return False
    if len(query_strings) > 1:
        _logger.warning(f'{len(query_strings)} query string urls are found (expected 1)')
        _logger.debug(f'Query string urls: {query_strings}')
    query_string = query_strings[0]
    _logger.debug(f'Used query string url: {query_string}')
    query_string = query_string[query_string.find(_index_url) + len(_index_url):]
    _logger.info(f'Used query string: {query_string}')
    query_string = urllib.parse.quote(query_string)
    _logger.debug(f'Used encoded query string: {query_string}')
    encoded_data = get_post_data(query_string, _global_config.ENCODING)
    _logger.debug(f'Post Data: {encoded_data}')
    login_request = urllib.request.Request(_request_url, data=encoded_data)
    add_default_headers(login_request)
    with urllib.request.urlopen(login_request) as response:
        _logger.info(f'Response Code: {response.code}')
        _logger.debug(f'Response: {response}\nMessage: {response.msg}\nReason: {response.reason}\nLength: {response.length}\nURL: {response.url}')
        _logger.debug(f'Headers: {response.headers.items()}')
        _logger.info(f'Response Content: {response.read().decode(_global_config.ENCODING)}')
    return True

_NOT_NONE = object()
def login_routine():
    # if the login process encounters no problem, return a not None value,
    # other wise using the default return value None to match
    # cases that exception occurs
    _logger.info(f'Detecting current status')
    if detect_connected():
        _logger.info('Status: CONNECTED')
        return _NOT_NONE
    _logger.info('Status: NOT CONNECTED')
    if not login():
        _logger.error('Login failed; The log messages may contain the reason')
    if detect_connected():
        _logger.info('Login successfully and the network status is CONNECTED now')
        return _NOT_NONE
    _logger.error('Login task is done but the network status is still NOT CONNECTED')
    _logger.error('The response from portal server may contain the reason')
    _logger.error('The problem is likely caused by incorrect login configuration')

class Opcode:
    nop = 0
    error = 1
    exec_exit = 2
    update_timeout = 3
    exec_init = 4
    exec_run = 5

def type_name(obj):
    return type(obj).__qualname__

def daemon_update(key, value):
    setattr(_global_config, key, value)
    return f'Updated {key} = {type_name(value)}({value})'

def daemon_get(key, source=_global_config):
    target = getattr(source, key)
    return f'{key} = {type_name(target)}({target})'

def daemon_exec_handler(command):
    return getattr(Opcode, f'exec_{command.name}'), f'Opcode exec_{command.name}'

def daemon_check_key(key, source=_global_config):
    if not hasattr(source, key):
        raise commands.CommandError(f'unknown key: {key}')

def daemon_update_handler(command):
    daemon_check_key(command.args.key)
    to_value = command.args.value
    if command.name == 'update_eval':
        to_value = ast.literal_eval(to_value)
    return Opcode.nop, daemon_update(command.args.key, to_value)

def daemon_update_timeout_handler(command):
    return Opcode.update_timeout, daemon_update('TEST_INTERVAL', float(command.args.value))

def daemon_get_handler(command):
    daemon_check_key(command.args.key)
    return Opcode.nop, daemon_get(command.args.key)

_ALLOWED_GET_GLOBAL = True
_DEFAULT = object()
def daemon_inspect_handler(command):
    if not _ALLOWED_GET_GLOBAL:
        raise commands.CommandError('Operation not permitted')
    frame = sys._getframe(0)
    for _ in range(int(command.args.depth)):
        frame = frame.f_back
        if frame is None:
            raise commands.CommandError(f'Not frame available at depth {command.args.depth}')
    source = getattr(frame, command.args.space, None)
    if source is None:
        raise commands.CommandError(f'Failed to get {command.args.space} from the frame')
    if isinstance(source, dict):
        _self = source.pop('self', _DEFAULT)
        source = argparse.Namespace(**source)
        if _self is not _DEFAULT:
            setattr(source, 'self', _self)
    if not isinstance(command.args.key, str):
        return Opcode.nop, ', '.join(dir(source))
    daemon_check_key(command.args.key, source)
    return Opcode.nop, daemon_get(command.args.key, source)

def daemon_help_handler(command):
    manager = getattr(command.parser, commands._MANAGER_ATTR, None)
    if manager is None:
        raise commands.CommandError('Manager not found; Help message is not available')
    return Opcode.nop, manager.help_message(command.args.command)

def daemon_execute(manager, command):
    try:
        return manager.execute(command)
    except commands.CommandError as e:
        return Opcode.error, str(e)
    except Exception as server_side_exc:
        _logger.warning(traceback.format_exc())
        return Opcode.error, f'ServerSideException {server_side_exc}'

def daemon_execute_legacy(command):
    args = command.strip().split()
    msg = command
    if not args:
        msg = f'Could not parse command {command}'
        _logger.warning(msg)
        return Opcode.error, msg
    _logger.info(f'Executing {args}')
    if args[0] in ('exit', 'init', 'run'):
        return getattr(Opcode, f'exec_{args[0]}'), msg
    elif args[0] in ('update', 'update_eval'):
        if not hasattr(_global_config, args[1]):
            _logger.warning(f'Unknown key: {args[1]}')
        to_value = ast.literal_eval(args[2]) if args[0] == 'update_eval' else args[2]
        return Opcode.nop, daemon_update(args[1], to_value)
    elif args[0] == 'update_timeout':
        return Opcode.update_timeout, daemon_update('TEST_INTERVAL', float(args[1]))
    elif args[0] == 'get':
        if not hasattr(_global_config, args[1]):
            _logger.warning(f'Unknown key: {args[1]}')
        return Opcode.nop, daemon_get(args[1])
    else:
        msg = f'Unknown command {args[0]}'
        _logger.info(msg)
        return Opcode.nop, msg

def safe_run(routine):
    try:
        return routine()
    except Exception as e:
        _logger.error(f'Error {e} occurs when executing routine {routine}')
        _logger.error(traceback.format_exc())

def generate_daemon_key(fp):
    daemon_key = crypt_utils.generate_key(32)
    daemon_key_bytes = daemon_key.encode()
    daemon_key_hash = hashlib.sha256(daemon_key_bytes).hexdigest().encode()
    _logger.info(f'Daemon key is generated to {fp}')
    with open(fp, 'w') as f:
        f.write(daemon_key)
    return daemon_key_bytes, daemon_key_hash

class ForcedTimeoutError(OSError):
    pass

def trigger_timeout(msg):
    raise ForcedTimeoutError(msg)

def init_daemon_commands():
    manager = commands.CommandsManager()
    manager.register('exit', desc='Exit the daemon', handler=daemon_exec_handler)
    manager.register('init', desc='Request daemon to initialize', handler=daemon_exec_handler)
    manager.register('run', desc='Request daemon to run the routine', handler=daemon_exec_handler)
    manager.register('update',
                     commands.ArgSet('key'),
                     commands.ArgSet('value'),
                     desc='Update a context attribute',
                     handler=daemon_update_handler)
    manager.register('update_eval',
                     parser=manager.get('update'),
                     desc='Similar to command update but the value will be computed',
                     handler=daemon_update_handler)
    manager.register('update_timeout',
                     commands.ArgSet('value'),
                     desc='Update TEST_INTERVAL and make it take effect',
                     handler=daemon_update_timeout_handler)
    manager.register('get',
                     commands.ArgSet('key'),
                     desc='Get value of a context attribute',
                     handler=daemon_get_handler)
    manager.register('inspect',
                     commands.ArgSet('key', nargs='?', default=0),
                     commands.ArgSet('-d', '--depth', required=False, default=4),
                     commands.ArgSet('-s', '--space', required=False, default='f_locals'),
                     desc='[DEBUG] Get daemon value at runtime',
                     handler=daemon_inspect_handler)
    manager.register('help',
                     commands.ArgSet('command', nargs='?', default=None),
                     desc='Print help message',
                     handler=daemon_help_handler)
    return manager

def start_daemon(daemon_file, address, port, routine, daemon_key_file):
    '''
    Run a daemon to test the network and try to login
    regularly. 

    The daemon is designed as runtime modifiable,
    and clients can communicate with the daemon using socket.

    The daemon has a OTP approach for client authentication.
    The OTP is stored in daemon_key_file. This password may also be
    used for encryption for clients' message.

    Context attributes are available for modify and get operations, 
    and clients can request the daemon to execute some predefined
    operations
    '''
    daemon_config = {}
    if os.path.exists(daemon_file):
        raise RuntimeError(f'Daemon file {daemon_file} exists')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        # Bind the socket to the address and port
        server_socket.settimeout(_global_config.TEST_INTERVAL)
        server_socket.bind((address, port))
        # Listen for incoming connections
        server_socket.listen(5)

        actual_socket = server_socket.getsockname()

        daemon_config['pid'] = os.getpid()
        daemon_config['address'] = actual_socket[0]
        daemon_config['port'] = actual_socket[1]
        if not _INIT_END:
            raise RuntimeError('Components are not initialized')
        _logger.info('Initializing daemon')
        daemon_key_bytes, daemon_key_hash = generate_daemon_key(daemon_key_file)
        _logger.info('Registering commands')
        manager = init_daemon_commands()
        _t_daemon_start = time.time()
        with open(daemon_file, 'w') as f:
            f.write(json.dumps(daemon_config))

        _logger.info(f"Daemon start listening on {actual_socket[0]}:{actual_socket[1]}")
        _logger.info(f'Run first routine {routine}')
        t_last_timeout = time.time()
        if safe_run(routine) is None and _global_config.FALLBACK_RETRY_INTERVAL > 0:
            _logger.info(f'Set timeout to {_global_config.FALLBACK_RETRY_INTERVAL} for retrying')
            server_socket.settimeout(_global_config.FALLBACK_RETRY_INTERVAL)

        while True:
            # Accept a connection from the client
            msg = None
            try:
                conn, addr = server_socket.accept()
                with conn:
                    _logger.info(f"Connected by {addr}")
                    # Receive a response from the client
                    client_key = conn.recv(len(daemon_key_hash))
                    _logger.info(f'Receive a client key {client_key}')
                    if client_key == daemon_key_hash:
                        _logger.info('The client is authenticated')
                        data = crypt_utils.xor(conn.recv(1024), daemon_key_bytes)
                        msg = data.decode()
                        _logger.info('Regenerating daemon key')
                        daemon_key_bytes, daemon_key_hash = generate_daemon_key(daemon_key_file)
                    else:
                        _logger.info('The client connection is illegal')
                        conn.sendall('[-1] Connection refused; Reason: Incorrect daemon key'.encode())
                    if msg is not None:
                        opcode, response_msg = daemon_execute(manager, msg)
                        msg_to_client = f'[{opcode}] {response_msg}'
                        _logger.info(f'Send to client: {msg_to_client}')
                        conn.sendall(msg_to_client.encode())
                        if opcode == Opcode.exec_exit:
                            break
                        elif opcode == Opcode.exec_init:
                            init()
                        elif opcode == Opcode.update_timeout:
                            t_last_timeout = time.time()
                            server_socket.settimeout(_global_config.TEST_INTERVAL)
                            continue
                        elif opcode == Opcode.exec_run:
                            trigger_timeout('Forced execution')
                t_from_last_timeout = time.time() - t_last_timeout
                _logger.debug(f'Time elapsed from last timeout: {t_from_last_timeout}')
                t_to_next_timeout = server_socket.gettimeout() - t_from_last_timeout
                _logger.debug(f'Time to next timeout: {t_to_next_timeout}')
                if t_to_next_timeout > 0:
                    # This line does not mean there is a real timeout
                    # event occurs. It is just used to reset the start point
                    # of the timing so that we can correctly compute t_to_next_timeout
                    # otherwise t_to_next_timeout will be less because we substract
                    # the substracted t_last_timeout value twice, to fix that
                    # t_to_next_timeout should be computed using last not temporary
                    # To do that we should update this not temporary timeout
                    # each time we set a not temporary timeout.
                    t_last_timeout = time.time()
                    _logger.debug(f'Set time to next timeout {t_to_next_timeout} as temporary timeout')
                    server_socket.settimeout(t_to_next_timeout)
                    continue
                _logger.warning('A scheduled timeout event does not occur; Try to trigger it')
                trigger_timeout('Forcibly run out the test interval')
            except OSError as err:
                _logger.info(f'Test interval ran out; {err}')
                t_last_timeout = time.time()
                if safe_run(routine) is None and _global_config.FALLBACK_RETRY_INTERVAL > 0:
                    _logger.info(f'Set timeout to {_global_config.FALLBACK_RETRY_INTERVAL} for retrying')
                    server_socket.settimeout(_global_config.FALLBACK_RETRY_INTERVAL)
                    continue
                if server_socket.gettimeout() != _global_config.TEST_INTERVAL:
                    _logger.info(f'Reset timeout to {_global_config.TEST_INTERVAL}')
                    server_socket.settimeout(_global_config.TEST_INTERVAL)
            except Exception as e:
                _logger.error(e)
                _logger.error(traceback.format_exc())
    _logger.info(f'Removing daemon file {daemon_file}')
    os.remove(daemon_file)
    _logger.info(f'Removing daemon key file {daemon_key_file}')
    os.remove(daemon_key_file)
    _logger.info(f'Daemon running time: {time.time() - _t_daemon_start}s')
    _logger.info('Daemon exited')


def client_send(daemon_file, message, daemon_key_file, daemon_key):
    '''
    Run a client who sends commands to the daemon,
    so that we can interact with the daemon runtime.

    The key will be hashed using SHA-256 and sent to 
    the daemon for identification. Then this OTP is 
    used to encrypt the message which is about to send.
    '''
    if not message:
        raise RuntimeError('Sending empty message is not allowed')
    if not os.path.exists(daemon_file):
        raise RuntimeError(f'Daemon file {daemon_file} does not exist')
    with open(daemon_file, 'r') as f:
        daemon = json.load(f)
    if daemon_key is None:
        if os.path.exists(daemon_key_file):
            with open(daemon_key_file, 'r') as f:
                daemon_key = f.read().strip()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        # Connect to the server
        client_socket.connect((daemon['address'], daemon['port']))

        daemon_key_bytes = daemon_key.encode()
        daemon_key_hash = hashlib.sha256(daemon_key_bytes).hexdigest().encode()
        client_socket.sendall(daemon_key_hash)

        # Send a message to the server
        client_socket.sendall(crypt_utils.xor(message.encode(), daemon_key_bytes))
        result = client_socket.recv(1024).decode()
        print(result)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', required=False, default=0)
    parser.add_argument('-n', '--network', required=False, default='localhost')
    parser.add_argument('-d', '--daemon', required=False, default=False, action='store_true')
    parser.add_argument('-f', '--daemon-file', required=False, default='./login_daemon.json')
    parser.add_argument('-m', '--message', required=False, default='Hello')
    parser.add_argument('-i', '--daemon-key-file', required=False, default='./login_daemon_key')
    parser.add_argument('-k', '--daemon-key', required=False, default=None)
    args = parser.parse_args()
    if args.daemon:
        init()
        start_daemon(args.daemon_file, args.network, args.port, login_routine, args.daemon_key_file)
    else:
        client_send(args.daemon_file, args.message, args.daemon_key_file, args.daemon_key)

if __name__ == '__main__':
    main()