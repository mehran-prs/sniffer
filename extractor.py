import time
import json

import datetime

import os


class Extractor:
    def __init__(self, interval):
        self.last_update = time.time()
        self.interval = interval  # write data each 5 minutes

    def import_base_data(self):
        fname = self.fname()

        if not os.path.exists(fname):
            return {}
        else:
            with open(fname, encoding='utf-8') as F:
                return json.loads(F.read())

    def fname(self):
        d = datetime.datetime.now()
        d = d.strftime('%Y-%m-%d')
        return '/var/sniffer/res/res-' + d + '.json'

    def should_update(self):
        return (self.last_update - time.time() / 60) > self.interval

    def update(self, data):
        with open(self.fname(), 'w') as fp:
            json.dump(data, fp)

        self.last_update = time.time()
