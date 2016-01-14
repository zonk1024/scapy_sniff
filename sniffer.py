#!/usr/bin/env python

from sys import argv
from Queue import Queue
from scapy.all import sniff
from threading import Thread


class Sniffer(object):

    def __init__(self, *args, **kwargs):
        self.started = False
        self._stop = False
        self._once = False
        self.queue = Queue()
        kwargs['prn'] = self.prn_func
        self.args = args
        self.kwargs = kwargs
        self.start()

    def stop(self):
        if not hasattr(self, '_thread'):
            raise Exception('Kill what?')
        self._stop = True
        self.started = False

    def prn_func(self, value):
        if self._stop:
            raise Exception('Stop thread')
        self._once = True
        self.queue.put(value)

    def sniff(self):
        try:
            sniff(*self.args, **self.kwargs)
        except Exception as e:
            if not self._once:
                print 'Exception on thread:', repr(e), '\n', self.args, '\n', self.kwargs, '\n\n'
                print 'Since I didn\'t have a single success you should probably be reminded to use sudo'
                raise
        self.stop()
        self.queue.put(None)  # make sure things have an iteration after thread stops

    def start(self):
        if hasattr(self, '_thread'):
            raise Exception('Already started')
        self._thread = Thread(target=self.sniff)
        self._thread.daemon = True
        self.started = True
        self._thread.start()

    def __iter__(self):
        while True:
            value = self.queue.get()
            if value is not None:
                yield value
            else:
                break
        self._thread.join()
        del self._thread
        self._stop = False


if __name__ == '__main__':
    # just proof of concept here
    sniff_filter = None
    try:
        sniff_filter = argv[1]
    except:
        pass
    sniffer = Sniffer(filter=sniff_filter, count=8)  #TODO argparse (dynamic?) *args, **options for cli
    print 'Running once'
    for i, p in enumerate(sniffer):
        print '\n', i
        p.show()

    sniffer.start()
    print 'Running again'
    for i, p in enumerate(sniffer):
        print '\n', i
        p.show()

    print 'Ran twice'
