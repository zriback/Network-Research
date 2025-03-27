import random
import subprocess as sp

ITERATIONS = 10000
PING_COMMAND_FORMAT = 'ping -n {} {}'
NUM_ECHO_REQUESTS = 4

IPS = [
    '8.8.8.8',
    '1.1.1.1',
    '129.21.3.17',
    '129.21.4.18',
    '129.21.127.92',
    'example.com',
    'youtube.com',
    'google.com',
    'yahoo.com',
    'amazon.com',
    'rit.edu',
    'cloudflare.com'
]


def main():
    for i in range(ITERATIONS):
        ip = random.choice(IPS)
        ping_command = PING_COMMAND_FORMAT.format(NUM_ECHO_REQUESTS, ip)
        ping_process = sp.Popen(ping_command.split())
        
        ping_process.wait()

        if i % 10 == 0:
            print('Completed', i, 'pings')

        
if __name__ == '__main__':
    main()

