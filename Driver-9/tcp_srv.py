#-*- coding:utf-8 -*-
from socket import *
from time import ctime

HOST = ''
PORT = 23333
BUFSIZ = 1024
ADDR = (HOST, PORT)

tcpSerSock = socket(AF_INET, SOCK_STREAM)
tcpSerSock.bind(ADDR)
tcpSerSock.listen(5)

while True:
    print 'waiting for connection...'
    tcpCliSock, addr = tcpSerSock.accept()
    print '...connected from:', addr
	
    while True:
        try:
            data = tcpCliSock.recv(BUFSIZ)
            if not data:
                break
            print data
        except:
            break
    tcpCliSock.close()

tcpSerSock.close()