#!/usr/bin/env python
# -*- coding:UTF-8 -*-

from socket import *
from time import ctime

HOST = '0.0.0.0'
PORT = 43333
BUFSIZE = 1024

ADDR = (HOST,PORT)

udpSerSock = socket(AF_INET, SOCK_DGRAM)
udpSerSock.bind(ADDR)

while True:
	print 'wating for message...'
	data, addr = udpSerSock.recvfrom(BUFSIZE)
	print data
	#udpSerSock.sendto('[%s] %s'%(ctime(),data),addr)
	print '...received from :',addr

udpSerSock.close()
