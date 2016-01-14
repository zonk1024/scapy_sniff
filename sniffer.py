#!/usr/bin/env python

from sys import argv
from Queue import Queue
from scapy.all import sniff
from threading import Thread


class Sniffer(object):

    def __init__(self, *args, **kwargs):
        self.started = False
        self._kill = False
        self._once = False
        self.queue = Queue()
        kwargs['prn'] = self.prn_func
        self.args = args
        self.kwargs = kwargs
        self.start()

    def kill(self):
        self._kill = True

    def prn_func(self, value):
        if self._kill:
            raise Exception('Stop thread')
        self._once = True
        self.queue.put(value)

    def sniff(self):
        try:
            sniff(*self.args, **self.kwargs)
        except Exception as e:
            if not self._once:
                print 'Exception on thread:', repr(e), '\n', self.args, '\n, self.kwargs, '\n\n'
                print 'Since I didn\'t have a single succes you should probably be reminded to use sudo'
                raise
        self.kill()
        self.queue.put(None)  # make sure things have an iteration after thread stops

    def start(self):
        if hasattr(self, '_thread'):
            raise Exception('Already started')
        self._thread = Thread(target=self.sniff)
        self._thread.daemon = True
        self.started = True
        self._thread.start()

    def __iter__(self):
        while not self._kill:
            value = self.queue.get()
            if value is not None:
                yield value


if __name__ == '__main__':
    sniffer = Sniffer(filter=argv[1], count=128)  #TODO argpars (dynamic?) *args, **options
    print 'Running'
    for i, p in enumerate(sniffer):
        print i,
        p.show()
