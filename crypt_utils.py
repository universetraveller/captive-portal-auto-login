import string
import secrets
class KeyConsumer:
    def __init__(self, key):
        self.key = key
        self.cur = 0
        self.length = len(key)
        if self.length == 0:
            raise RuntimeError('Empty key is not allowed')
    
    def step(self, n=1):
        self.cur += n
        return self.cur

    def _consume(self, n=1):
        if self.cur + n < self.length:
            return self.key[self.cur:self.step(n)]
        base = self.key[self.cur:]
        self.cur = 0
        return base + self.consume(n - len(base))

    def consume(self, n=1):
        return n // self.length * self.key + self.key[self.cur:self.step(n % self.length)]

class XORCrypt:
    def __init__(self, input: bytes, key: bytes):
        self.key_consumer = KeyConsumer(key)
        self.content = list(input)
        self.length = len(self.content)
        if self.length == 0:
            def _raise():
                raise RuntimeError('This method is removed because it can not handle this input')
            self.run_n = _raise

    def run(self):
        key = self.key_consumer.consume(self.length)
        for i in range(self.length):
            self.content[i] ^= key[i] 

    def run_n(self, n=None):
        if n is None:
            n = self.key_consumer.length // self.length
            if self.key_consumer.length % self.length:
                n += 1
        for _ in range(n):
            self.run()

    def get(self):
        return bytes(self.content)

def xor(input, key):
    runner = XORCrypt(input, key)
    runner.run()
    return runner.get()

alphabet = string.ascii_letters + string.digits
def generate_key(length):
    return ''.join(secrets.choice(alphabet) for _ in range(length))