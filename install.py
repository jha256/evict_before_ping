import paramiko
from os import system
from config import config

def install():
    global config
    
    #change the IP and keys according to config.py
    
    victimIP = config_victim['IP']
    victimKey = config_victim['Key']
    adversaryIP = config_adversary['IP']
    adversaryKey = config_adversary['Key']
    
    print('connecting to victim instance...')
    victim = paramiko.SSHClient()
    victim.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    victim.connect(victimIP, username="ubuntu", pkey=paramiko.RSAKey.from_private_key_file(victimKey))
    
    print('connecting to adversary instance...')
    adversary = paramiko.SSHClient()
    adversary.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    adversary.connect(adversaryIP, username="ubuntu", pkey=paramiko.RSAKey.from_private_key_file(adversaryKey))

    print('initializing victim instance...')
    
    print('sending bitcoin binaries to victim...')
    system('scp -i {} bitcoind ubuntu@{}:/home/ubuntu'.format(victimKey, victimIP))
    system('scp -i {} bitcoin-cli ubuntu@{}:/home/ubuntu'.format(victimKey, victimIP))
    
    print('sending analysis scripts to victim...')
    system('scp -i {} deploy/victim/analyze.py ubuntu@{}:/home/ubuntu'.format(victimKey, victimIP))
    system('scp -i {} config.py ubuntu@{}:/home/ubuntu'.format(victimKey, victimIP))
    
    print('installing dependencies...')
    _, stdout, _ = victim.exec_command('sudo apt-get update')
    stdout.channel.recv_exit_status()
    _, stdout, _ = victim.exec_command('sudo apt-get -y upgrade')
    stdout.channel.recv_exit_status()
    _, stdout, _ = victim.exec_command('sudo apt-get -y install build-essential libtool autotools-dev automake pkg-config bsdmainutils python3 libevent-dev libboost-dev libboost-system-dev libboost-filesystem-dev libboost-test-dev libboost-thread-dev libzmq3-dev')
    stdout.channel.recv_exit_status()
    
    print('making bitcoin config file...')
    _, stdout, _ = victim.exec_command('mkdir /home/ubuntu/.bitcoin')
    stdout.channel.recv_exit_status()
    _, stdout, _ = victim.exec_command('echo -e "rpcuser=1234\\nrpcpassword=1234\\ndebug=1\\n" > /home/ubuntu/.bitcoin/bitcoin.conf')
    stdout.channel.recv_exit_status()

    print('initializing adversary instance...')
    print('sending attack script to adversary...')
    system('scp -i {} attack.py ubuntu@{}:/home/ubuntu'.format(adversaryKey, adversaryIP))
    system('scp -i {} config.py ubuntu@{}:/home/ubuntu'.format(adversaryKey, adversaryIP))
    print('installing dependencies...')
    _, stdout, _ = adversary.exec_command('sudo apt-get update')
    stdout.channel.recv_exit_status()
    _, stdout, _ = adversary.exec_command('sudo apt-get -y upgrade')
    stdout.channel.recv_exit_status()

if __name__ == '__main__':
    install()
