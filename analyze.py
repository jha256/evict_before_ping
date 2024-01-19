# ADVERSARY = 1, BENIGN = 2

class Peer():
    def __init__(self):
        self.nodetype = None
        self.ping = False
        self.evicted = False
        self.minpingtime = 99999

attacker_IP = '1.2.3.4' # change this IP
benign_cnt = 0
adversary_cnt = 0
peers = {} # store peers of the victim in dictionary -> id : peer
evict_before_ping_fail_list = set()
min_ping_time_list = list()

evict_before_ping = 0 # success evict-before-ping

# exceptional cases: benign peers with abnormal behaviour
type_two = 0
type_three = 0

with open('/home/ubuntu/.bitcoin/debug.log', 'rt') as f:
    while True:
        line = f.readline()
        if not line:
            break
        if 'connection from' in line:
            # Where a new peer made a TCP connection with the victim (ONLY INBOUND CONNECTIONS!).
            # ex) 2022-05-12T11:50:14Z connection from 49.83.141.163:55900 accepted with peer=1845
            peerIP = line.strip().split(' ')[-4].split(':')[0]
            peerid = int(line.strip().split(' ')[-1].split('=')[1])
            # Declare Peer() instance, and check whether it's BENIGN or ADVERSARY
            peers[peerid] = Peer()
            if peerIP == attacker_IP:
                peers[peerid].nodetype = 1 # ADVERSARY
                adversary_cnt += 1
            else:
                peers[peerid].nodetype = 2 # BENIGN
                benign_cnt += 1
        elif 'received: pong' in line:
            # Finished ping-pong message exchange with the peer.
            # ex) 2022-05-16T14:31:07Z received: pong (8 bytes) peer=31397
            peerid = int(line.strip().split(' ')[-1].split('=')[1])
            if (peerid in peers.keys()) and (peers[peerid].nodetype == 2):
                peers[peerid].ping = True
                evict_before_ping_fail_list.add(peerid)
        elif 'pong received with' in line:
            # Checking the pingtimes of the BENIGN peers which received PONG
            # ex) 2022-05-16T14:31:07Z pong received with peer=31397, pingtime=1.49321
            pingtime = float(line.strip().split(' ')[-1].split('=')[1])
            peerid = int(line.strip().split(' ')[-2][:-1].split('=')[1])
            if (peerid in peers.keys()) and (peers[peerid].nodetype == 2):
                if peers[peerid].minpingtime > pingtime:
                    peers[peerid].minpingtime = pingtime
        elif 'selected inbound connection' in line:
            # Evicting peer whether it's BENIGN or ADVERSARY
            # ex) 2022-05-19T06:59:55Z selected inbound connection for eviction peer=114; disconnecting
            peerid = int(line.strip().split(' ')[-2][:-1].split('=')[1])
            if (peerid in peers.keys()) and (peers[peerid].nodetype == 2):
                if peers[peerid].ping == False:
                    evict_before_ping += 1                
                peers[peerid].evicted = True
        # Below cases are benign peers disconnected under unexpected behavior. "type 2, type 3" are logged by modified bitcoin client.
        elif 'type 2' in line:
            peerid = int(line.strip().split(' ')[-1].split('=')[1])
            if peerid in peers.keys() and peers[peerid].nodetype == 2:
                if peers[peerid].ping == False:
                    type_two += 1
        elif 'type 3' in line:
            peerid = int(line.strip().split(' ')[6][:-1].split('=')[1])
            if peerid in peers.keys() and peers[peerid].nodetype == 2:
                if peers[peerid].ping == False:
                    type_three += 1

for k in peers.values():
    if k.minpingtime < 99999:
        min_ping_time_list.append(k.minpingtime)

print('minpingtime of benign peers which failed to evict_before_ping: '+ str(sorted(min_ping_time_list)))
print('{}/{}'.format(type_two, type_three))
print('# of incoming benign connections: '+str(benign_cnt))
print('# of incoming adversarial connections: '+str(adversary_cnt))
print('{}/{}'.format(evict_before_ping, len(evict_before_ping_fail_list)))
