#!/usr/bin/python
import socket
import select
import time
import sys
import argparse
import hashlib

buffer_size = (4096*2)
delay = 0.0001

class Encryptor:
    def __init__(self, key):
        key = self.convert_key(key)
        self.keystream = self.RC4(key)
        for i in range(0, 1024, 1):
            self.keystream.next()

    def convert_key(self, key):
        return [ord(c) for c in key]

    def KSA(self, key):
        keylength = len(key)
        S = range(256)
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % keylength]) % 256
            S[i], S[j] = S[j], S[i] 
        return S

    def PRGA(self, S):
        i = 0
        j = 0
        while True:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            K = S[(S[i] + S[j]) % 256]
            yield K

    def RC4(self, key):
        S = self.KSA(key)
        return self.PRGA(S)

    def XOR(self, plaintext):
        cipher = ''
        for c in plaintext:
            cipher = cipher + chr(ord(c) ^ self.keystream.next())
        return cipher

class Forward:
    def __init__(self):
        self.forward = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self, host, port):
        try:
            self.forward.connect((host, port))
            return self.forward
        except Exception, e:
            print e
            return False

class ProxyServer:
    input_list = []
    channel = {}
    keystream = {}
    fhost = ''
    fport = 0

    def __init__(self, host, port, fhost, fport, pKey):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))
        self.server.listen(200)
        self.fhost = fhost
        self.fport = fport
        self.pKey = pKey
        print "listening on: "+str(host)+":"+str(port)
        print "forwarding (rc4): "+str(fhost)+":"+str(fport)

    def main_loop(self):
        self.input_list.append(self.server)
        while 1:
            time.sleep(delay)
            ss = select.select
            inputready, outputready, exceptready = ss(self.input_list, [], [])
            for self.s in inputready:
                if self.s == self.server:
                    self.on_accept()
                    break

                self.data = self.s.recv(buffer_size)
                if len(self.data) == 0:
                    self.on_close()
                    break
                else:
                    self.on_recv()

    def on_accept(self):
        forward = Forward().start(self.fhost, self.fport)
        clientsock, clientaddr = self.server.accept()
        if forward:
            print clientaddr, "has connected"
            self.input_list.append(clientsock)
            self.input_list.append(forward)
            self.channel[clientsock] = forward
            self.channel[forward] = clientsock
            #SHA256 private key with nonce per forward request on connect
            rc4 = Encryptor(hashlib.sha256(self.pKey + str(time.time())[:8]).hexdigest())
            #MITM!
            self.keystream[clientsock] = rc4
            self.keystream[forward] = rc4

        else:
            print "Can't establish connection with remote server.",
            print "Closing connection with client side", clientaddr
            clientsock.close()

    def on_close(self):
        print self.s.getpeername(), "has disconnected"
        self.input_list.remove(self.s)
        self.input_list.remove(self.channel[self.s])
        out = self.channel[self.s]
        self.channel[out].close()  
        self.channel[self.s].close()
        del self.channel[out]
        del self.channel[self.s]

    def on_recv(self):
        print "RAW: " + self.data
        print str([ord(c) for c in self.data])
        data = self.keystream[self.s].XOR(self.data)
       
        print "XOR: "+ data
        print str("Sent by: " + str(self.s) + " to " + str(self.channel[self.s]))
        self.channel[self.s].send(data)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Simple TCP port forwarder w/ RC4 encryptor/decryptor.')
    parser.add_argument('-l', type=str, help='Listen on x.x.x.x:xxxx')
    parser.add_argument('-t', type=str, help='Tunnel to x.x.x.x:xxxx')
    parser.add_argument('-p', type=str, help='Secret: `openssl passwd -1 -salt xxxxxxxx`')
    args = parser.parse_args()
    server = ProxyServer(args.l.split(":")[0], int(args.l.split(":")[1]), args.t.split(":")[0], int(args.t.split(":")[1]), args.p)
    try:
        server.main_loop()
    except KeyboardInterrupt:
        print "Ctrl C - Stopping server"
        sys.exit(1)
