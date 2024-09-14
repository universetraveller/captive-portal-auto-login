import urllib.request
class FailedResponse:
    def __init__(self, errno=-1, msg='', url=''):
        self.code = errno
        self.msg = msg.encode()
        self.url = url

    def read(self):
        return self.msg

class BaseDetector:
    def __init__(self, address, timeout=5, encoding='utf-8'):
        self._type = 'Basic'
        self.address = address
        self.timeout = timeout
        self.reset_history()
        self.encoding = encoding

    def __repr__(self) -> str:
        return f'{self._type}(address="{self.address}", timeout={self.timeout}, encoding="{self.encoding}")'

    def get_last_redirect(self):
        return self.last_redirect

    def get_last_response(self):
        return self.last_response

    def reset_history(self):
        self.last_response = None
        self.last_redirect = None

    def make_response(self):
        # reset the history
        self.reset_history()
        try:
            response = urllib.request.urlopen(self.address, timeout=self.timeout)
        except OSError as err:
            # timeout
            response = FailedResponse(-1, str(err))
        self.last_response = response
        self.last_redirect = response.read().decode(self.encoding)

    def detect(self):
        raise NotImplementedError('Not implemented')

class CodeDetector(BaseDetector):
    def __init__(self, address, accept_code=204, timeout=5, encoding='utf-8'):
        super().__init__(address, timeout, encoding)
        self._type = 'CodeDetector'
        self.accept_code = accept_code

    def detect(self):
        self.make_response()
        return self.last_response.code == self.accept_code

def str_match(a, b):
    return a == b

def pattern_match(p, a):
    return p.match(a)

class ContentDetector(CodeDetector):
    def __init__(self, address, accept_content='Success', timeout=5, encoding='utf-8'):
        super().__init__(address, accept_content, timeout, encoding)
        self._type = 'ContentDetector'
        self.match = pattern_match
        if isinstance(accept_content, str):
            self.match = str_match
    
    def detect(self):
        self.make_response()
        return self.match(self.accept_code, self.last_redirect.strip())

class URLDetector(ContentDetector):
    def __init__(self, address, accept_content='Success', timeout=5, encoding='utf-8'):
        super().__init__(address, accept_content, timeout, encoding)
    
    def detect(self):
        self.make_response()
        return self.match(self.accept_code, self.last_response.url)

DETECTORS_GENERAL = [
    ContentDetector('http://captive.apple.com/', '<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>'),
    ContentDetector('http://www.apple.com/library/test/success.html', '<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>'),
    ContentDetector('http://www.msftconnecttest.com/connecttest.txt', 'Microsoft Connect Test'),
    CodeDetector('http://cp.cloudflare.com/'),
    ContentDetector('http://detectportal.firefox.com/success.txt', 'success'),
]
DETECTORS_CN = [
    CodeDetector('http://connect.rom.miui.com/generate_204'),
    CodeDetector('http://connectivitycheck.platform.hicloud.com/generate_204'),
    CodeDetector('http://wifi.vivo.com.cn/generate_204'),
]
DETECTORS_GLOBAL = [
    CodeDetector('http://connectivitycheck.gstatic.com/generate_204'),
    CodeDetector('http://www.google.com/generate_204'),
    CodeDetector('http://www.gstatic.com/generate_204'),
    CodeDetector('http://www.google-analytics.com/generate_204')
]

def test_detectors(detectors, expected):
    for detector in detectors:
        if bool(detector.detect()) != expected:
            raise AssertionError(f'Detector {detector} does not work')

def test_connected():
    test_detectors(DETECTORS_GENERAL, True)
    test_detectors(DETECTORS_CN, True)
    print('PASS')

def test_connected_global():
    test_detectors(DETECTORS_GLOBAL, True)
    print('PASS')

def test_not_connected():
    test_detectors(DETECTORS_GENERAL, False)
    test_detectors(DETECTORS_CN, False)
    test_detectors(DETECTORS_GLOBAL, False)
    for detector in DETECTORS_CN + DETECTORS_GENERAL:
        if detector.get_last_redirect() is None:
            raise AssertionError(f'Detector {detector} has no redirected url')
    print('PASS')