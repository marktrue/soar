#coding=utf8
#!/usr/bin/python
import struct,socket
import hashlib
import threading,random
import time
from base64 import b64encode, b64decode


#config
HOST = '0.0.0.0'
PORT = 3368

connectionlist = {}
g_code_length = 0
g_header_length = 0


def hex2dec(string_num):
    return str(int(string_num.upper(), 16))


def get_datalength(msg):
    global g_code_length
    global g_header_length

    print (len(msg))
    g_code_length = ord(msg[1]) & 127
    received_length = 0;
    if g_code_length == 126:
        #g_code_length = msg[2:4]
        #g_code_length = (ord(msg[2])<<8) + (ord(msg[3]))
        g_code_length = struct.unpack('>H', str(msg[2:4]))[0]
        g_header_length = 8
    elif g_code_length == 127:
        #g_code_length = msg[2:10]
        g_code_length = struct.unpack('>Q', str(msg[2:10]))[0]
        g_header_length = 14
    else:
        g_header_length = 6
    g_code_length = int(g_code_length)
    return g_code_length

def parse_data(msg):
    global g_code_length
    g_code_length = ord(msg[1]) & 127
    received_length = 0;
    if g_code_length == 126:
        g_code_length = struct.unpack('>H', str(msg[2:4]))[0]
        masks = msg[4:8]
        data = msg[8:]
    elif g_code_length == 127:
        g_code_length = struct.unpack('>Q', str(msg[2:10]))[0]
        masks = msg[10:14]
        data = msg[14:]
    else:
        masks = msg[2:6]
        data = msg[6:]


    i = 0
    raw_str = ''


    for d in data:
        raw_str += chr(ord(d) ^ ord(masks[i%4]))
        i += 1


    print (u"总长度是：%d" % int(g_code_length))
    return raw_str


def sendMessage(message):
    global connectionlist
    
    message_utf_8 = message.encode('utf-8')
    for connection in connectionlist.values():
        back_str = []
        back_str.append('\x81')
        data_length = len(message_utf_8)
        
        
        if data_length <= 125:
            back_str.append(chr(data_length))
        elif data_length <= 65535:
            back_str.append(struct.pack('b', 126))
            back_str.append(struct.pack('>h', data_length))
        elif data_length <= (2^64-1):
            back_str.append(struct.pack('b', 127))
            back_str.append(struct.pack('>q', data_length))
        else :
                print (u'太长了')
        msg = ''
        for c in back_str:
            msg += c;
        back_str = str(msg)   + message_utf_8#.encode('utf-8')
        if back_str != None and len(back_str) > 0:
            print (back_str)
            connection.send(back_str)
            
            
def deleteconnection(item):
    global connectionlist
    del connectionlist['connection'+item]

class WebSocket(threading.Thread):
    
    GUID = 'd7387453-d1e2-40d7-9572-a4afce3557ce'
    
    def __init__(self, conn, index, name, remote, path='/'):
        threading.Thread.__init__(self)
        self.conn = conn
        self.index = index
        self.name = name
        self.remote = remote
        self.path = path
        self.buffer = ''
        self.buffer_utf8 = ''
        self.buffer_len = 0
        
    def run(self):
        print('Socket%s Start!' % self.index)
        headers = {}
        self.handshaken = False
        
        while True:
            if self.handshaken == False:
                print('Socket%s Start HandShake With %s!' %(self.index, self.remote))
                self.buffer += bytes.decode(self.conn.recv(1024))
                
                if self.buffer.find('\r\n\r\n') != -1:
                    header, data = self.buffer.split('\r\n\r\n', 1)
                    for line in header.split("\r\n")[1:]:
                        key, value = line.split(":", 1)
                        key = key.strip()
                        value = value.strip()
                        headers[key] = value
                        
                    headers["Location"] = ("ws://%s%s" % (headers["Host"], self.path))
                    key = headers['Sec-WebSocket-Key']
                    token = b64encode(hashlib.sha1(str.encode(str(key + self.GUID))).digest())

                    handshake = "HTTP/1.1 101 Switching Protocols\r\n"\
                        "Upgrade: websocket\r\n"\
                        "Connection: Upgrade\r\n"\
                        "Sec-WebSocket-Accept: " + bytes.decode(token) + "\r\n"\
                        "WebSocket-Origin: " + str(headers["Origin"]) + "\r\n"\
                        "WebSocket-Location: " + str(headers["Location"]) + "\r\n\r\n"

                    self.conn.send(str.encode(str(handshake)))
                    self.handshaken = True
                    print ('Socket %s Handshaken with %s success!' % (self.index, self.remote))
                    sendMessage(u'Welcome, ' + self.name + ' !')
                    self.buffer_utf8 = ""
                    g_code_length = 0

            else:
                global g_code_length
                global g_header_length
                msg = self.conn.recv(128)
                if len(msg) <= 0:
                    continue
                if g_code_length == 0:
                    get_datalength(msg)
                #接受的长度
                self.buffer_len = self.buffer_len + len(msg)
                self.buffer = self.buffer + msg
                if self.buffer_len - g_header_length < g_code_length :
                    continue
                else:
                    self.buffer_utf8 = parse_data(self.buffer) #utf8
                    msg_unicode = str(self.buffer_utf8).decode('utf-8', 'ignore') #unicode
                    if msg_unicode == 'quit':
                        print (u'Socket%s Logout!' % (self.index))
                        nowTime = time.strftime('%H:%M:%S', time.localtime(time.time()))
                        sendMessage(u'%s %s say: %s' % (nowTime, self.remote, self.name + ' Logout'))
                        deleteconnection(str(self.index))
                        self.conn.close()
                        break #退出线程
                    else:
                        #print (u'Socket%s Got msg:%s from %s!' % (self.index, msg_unicode, self.remote))
                        nowTime = time.strftime(u'%H:%M:%S', time.localtime(time.time()))
                        sendMessage(u'%s %s say: %s' % (nowTime, self.remote, msg_unicode))
                    #重置buffer和bufferlength
                    self.buffer_utf8 = ""
                    self.buffer = ""
                    g_code_length = 0
                    self.length_buffer = 0
            self.buffer = ""

class WebSocketServer(object):
    def __init__(self):
        self.socket = None
        
    def begin(self):
        print('WebSocket Server Start!') 
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.socket.bind((HOST,PORT))
        self.socket.listen(50)
        
        global connectionlist
        
        i=0
        while True:
            connection, address = self.socket.accept()
            
            username = address[0]
            newSocket = WebSocket(connection, i, username, address)
            newSocket.start() #开始线程,执行run函数
            connectionlist['connection' + str(i)] = connection
            i = i + 1
            
if __name__ == "__main__":
    server = WebSocketServer()
    server.begin()