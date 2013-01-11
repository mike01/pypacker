#!/usr/bin/env python

import pypacker
import time, unittest

class TestPerf(unittest.TestCase):
    rounds = 10000

    def setUp(self):
        self.start = time.time()
    def tearDown(self):
        print(self.rounds / (time.time() - self.start), " rounds/s")

    def test_pack(self):
        for i in range(self.rounds):
            str(pypacker.ip.IP())
        print("pack:", end=' ')

    def test_unpack(self):
        buf = str(pypacker.ip.IP())
        for i in range(self.rounds):
            pypacker.ip.IP(buf)
        print("unpack:", end=' ')
        
if __name__ == '__main__':
    unittest.main()
