import os
import subprocess as sp
import time
import ifaddr
import re
from functools import partial
import matplotlib.pyplot as plt
from matplotlib.ticker import FormatStrFormatter
import numpy as np
from dataclasses import dataclass
import platform
from enum import Enum

# "Linux" or "Windows"
# found when running the main function
os_name = ''

@dataclass
class CaptureData:
    num_packets: int = 0
    eth_num: int = 0
    ip_num: int = 0
    tcp_num: int = 0
    udp_num: int = 0
    average_length: float = 0
    src_mac_counts: dict = None
    dst_mac_counts: dict = None
    src_ip_counts: dict = None
    dst_ip_counts: dict = None
    eth_type_counts: dict = None
    ip_proto_counts: dict = None
    tcp_src_port_counts: dict = None
    tcp_dst_port_counts: dict = None
    udp_src_port_counts: dict = None
    udp_dst_port_counts: dict = None
    other_type_counts: dict = None
    microsec_times: list = None


CAPTURES_FILEPATH = 'captures'
CLEANED_FILEPATH = 'cleaned'

# Number of nibbles to extract from each packet as a feature from each packet
# The first NUM_FEATURES/2 bytes are extracted from each packet
NUM_FEATURES = 128

SAMPLES_PER_CLASS = 10000

# Maximum number of bars to display on a bar chart
MAX_BAR_CHART_BARS = 10

DEFAULT_COLOR = '\x1b[39m'
RED_COLOR = '\x1b[31m'
GREEN_COLOR = '\x1b[32m'
YELLOW_COLOR = '\x1b[33m'

# byte location information for IP and Ethernet headers
SRC_MAC_LOC = 6
DST_MAC_LOC = 0
ETH_TYPE_LOC = 12
SRC_IP_LOC = 26
DST_IP_LOC = 30
IP_PROTO_LOC = 23
IPV6_NEXT_HEADER_LOC = 20
SRC_PORT_LOC = 34
DST_PORT_LOC = 36
ARP_OPCODE_LOC = 20
ICMP_TYPE_LOC = 34

ETH_TYPES = {
    '0800' : 'IPv4',
    '0806' : 'ARP',
    '86dd' : 'IPv6',
    '9000' : 'LOOP'
}

IP_PROTOS = {
    '01' : 'ICMP',
    '06' : 'TCP',
    '11' : 'UDP',
    '3a' : 'ICMPv6'
}

TCP_SERVICE_PORTS = {
    '0050' : 'HTTP',
    '1f90' : 'HTTP-8080',
    '01bb' : 'TLS',
    '0089' : 'NBNS'
}

UDP_SERVICE_PORTS = {
    '0035' : 'DNS',
    '0043' : 'DHCP',
    '0044' : 'DHCP',
    '0089' : 'NBNS',
    '076c' : 'SSDP',
    '01bb' : 'QUIC'
}

ARP_OPCODES = {
    '0001' : 'ARP Request',
    '0002' : 'ARP Reply'
}

ICMP_TYPES = {
    '00' : 'ICMP Echo Reply',
    '08' : 'ICMP Echo Request'
}

class PACKET_LAYERS(Enum):
    ETHERNET = 1,
    IPV4 = 2,
    IPV6 = 3,
    ARP = 4,
    ICMP = 5,
    TCP = 7,
    UDP = 8

CLASSES = {
    # 'ARP Request': 0,
    # 'ARP Reply' : 1,
    # 'ICMP Echo Request' : 2,
    # 'ICMP Echo Reply' : 3,
    'TLS' : 0,
    'HTTP' : 1,
    'DNS' : 2,
    'QUIC' : 3,
    'Other' : 4
}

def green_print(msg: str) -> None:
    print(GREEN_COLOR + msg + DEFAULT_COLOR)

def red_print(msg: str) -> None:
    print(RED_COLOR + msg + DEFAULT_COLOR)

def yellow_print(msg: str) -> None:
    print(YELLOW_COLOR + msg + DEFAULT_COLOR)


def get_printable_ip(ip: str) -> str:
    if len(ip) != 4*2:
        return None
    return '.'.join(str(int(''.join(pair), 16)) for pair in zip(*[iter(ip)]*2))

def get_printable_mac(mac: str) -> str:
    if len(mac) != 6*2:
        return None
    return ':'.join(''.join(pair) for pair in zip(*[iter(mac)]*2))

def get_header_field(data: str, loc: int, length: int) -> str:
    return data[loc*2:(loc+length)*2]

# Partial functions for getting each header field
get_src_mac = partial(get_header_field, loc=SRC_MAC_LOC, length=6)
get_dst_mac = partial(get_header_field, loc=DST_MAC_LOC, length=6)
get_src_ip = partial(get_header_field, loc=SRC_IP_LOC, length=4)
get_dst_ip = partial(get_header_field, loc=DST_IP_LOC, length=4)
get_eth_type = partial(get_header_field, loc=ETH_TYPE_LOC, length=2)
get_ip_proto = partial(get_header_field, loc=IP_PROTO_LOC, length=1)
get_ipv6_proto = partial(get_header_field, loc=IPV6_NEXT_HEADER_LOC, length=1)
get_src_port = partial(get_header_field, loc=SRC_PORT_LOC, length=2)
get_dst_port = partial(get_header_field, loc=DST_PORT_LOC, length=2)
get_arp_opcode = partial(get_header_field, loc=ARP_OPCODE_LOC, length=2)
get_icmp_type = partial(get_header_field, loc=ICMP_TYPE_LOC, length=1)

def redact_packet_data(data: str, loc: int, length: int, required_layers: list[int]):
    if any(layer in get_packet_layers(data) for layer in required_layers) and (loc+length)*2 <= len(data):
        return data[:loc*2] + '0'*length*2 + data[(loc+length)*2:]
    else:
        return data

# Partial functions for redacting each header field
redact_src_mac = partial(redact_packet_data, loc=SRC_MAC_LOC, length=6, required_layers=[PACKET_LAYERS.ETHERNET])
redact_dst_mac = partial(redact_packet_data, loc=DST_MAC_LOC, length=6, required_layers=[PACKET_LAYERS.ETHERNET])
redact_src_ip = partial(redact_packet_data, loc=SRC_IP_LOC, length=4, required_layers=[PACKET_LAYERS.IPV4])
redact_dst_ip = partial(redact_packet_data, loc=DST_IP_LOC, length=4, required_layers=[PACKET_LAYERS.IPV4])
redact_eth_type = partial(redact_packet_data, loc=ETH_TYPE_LOC, length=2, required_layers=[PACKET_LAYERS.ETHERNET])
redact_ip_proto = partial(redact_packet_data, loc=IP_PROTO_LOC, length=1, required_layers=[PACKET_LAYERS.IPV4])
redact_ipv6_proto = partial(redact_packet_data, loc=IPV6_NEXT_HEADER_LOC, length=1, required_layers=[PACKET_LAYERS.IPV6])
redact_src_port = partial(redact_packet_data, loc=SRC_PORT_LOC, length=2, required_layers=[PACKET_LAYERS.TCP, PACKET_LAYERS.UDP])
redact_dst_port = partial(redact_packet_data, loc=DST_PORT_LOC, length=2, required_layers=[PACKET_LAYERS.TCP, PACKET_LAYERS.UDP])
redact_arp_opcode = partial(redact_packet_data, loc=ARP_OPCODE_LOC, length=2, required_layers=[PACKET_LAYERS.ARP])
redact_icmp_type = partial(redact_packet_data, loc=ICMP_TYPE_LOC, length=1, required_layers=[PACKET_LAYERS.ICMP])


def clear_screen():
    global os_name
    if os_name == 'Windows':
        os.system('cls')
    else:  # 'Linux'
        os.system('clear')


def run_cmd(command: str) -> str:
    '''Runs the given command. Returns the output'''
    command_process = sp.Popen(command.split(), stdout=sp.PIPE, stderr=sp.PIPE)
    output, error = command_process.communicate()
    return output


def print_menu():
    output = 'Select an option:\n'
    output += '\t(1) Capture Traffic\n'
    output += '\t(2) Clean Captures\n'
    output += '\t(3) Analyze Data\n'
    output += '\t(4) Extract Features\n'
    output += '\t(5) Redact Data'
    print(output)


def get_user_input(message: str, default, use_type: type, help=None):
    '''Get and return user input. Automatically ensures no errors and supports default options
    default must be the same type as is passed in use_type
    if default is "use timestamp" it will return the current timestamp'''
    while True:
        print(f'{message} (default is {default if default != "" else "empty"}): ', end='')
        user_input = input()
        if user_input == '':  # user is trying to use the default
            if default == 'use timestamp':
                print()
                return str(int(time.time()))
            elif default is None:
                clear_screen()
                red_print('No default value to use. Enter a valid value.\n')
                continue
            else:
                print()
                return default
        elif user_input == 'help' and help is not None:
            clear_screen()
            print(help)
            continue
        else:
            try:
                user_input = use_type(user_input)
            except ValueError:
                clear_screen()
                red_print('Enter a valid value\n')
                continue
        break
    print()
    return user_input


def redact_data():
    '''Gets user input for what data to redact from a user inputted cleaned capture'''
    files = [file for file in os.listdir(CLEANED_FILEPATH)]

    get_file_help = 'Choose from one of the below files to analyze.\nYou can also enter the number corresponding to the file.\n'
    for i, file in enumerate(files):
        get_file_help += ('\t' + str(i) + ' - ' + file + '\n')
    
    while True:
        user_selection = get_user_input('Enter the name or number of the file to analyze. Use "help" for help.', None, str, get_file_help)

        # check if the user is inputting a number
        try:
            user_num_selection = int(user_selection)
            # to execute this code, it must be a number
            if user_num_selection < 0 or user_num_selection >= len(files):
                red_print('That number is out of range.\n')
                continue
            target_filename = files[user_num_selection]
            # found a valid file
            break     
        except ValueError:  # not a number. User is entering a file name
            if not user_selection.endswith('.txt'):
                user_selection = user_selection + '.txt'
            if user_selection not in files:
                red_print(f'Could not find the file {user_selection}\n')
                continue
            # found a valid file
            target_filename = user_selection
            break

    default_output_name = target_filename[:target_filename.index('.txt')] + '_redacted.txt'
    while True:
        try:
            output_filename = get_user_input('Enter the output file name', default_output_name, str, None)
            if not output_filename.endswith('.txt'):
                output_filename += '.txt'
            if os.path.exists(output_filename):
                raise FileExistsError()
            break
        except FileExistsError:
            clear_screen()
            red_print('That output file already exists\n')

    # get function pointers for fields that should be redacted
    redact_func_dict = {
        0 : ['Source MAC', redact_src_mac],
        1 : ['Destination MAC', redact_dst_mac],
        2 : ['Source IP', redact_src_ip],
        3 : ['Destination IP', redact_dst_ip],
        4 : ['Ethernet Type', redact_eth_type],
        5 : ['IP Protocol', redact_ip_proto],
        6 : ['IPv6 Protocol', redact_ipv6_proto],
        7 : ['Source Port', redact_src_port],
        8 : ['Destination Port', redact_dst_port],
        9 : ['ARP Opcode', redact_arp_opcode],
        10 : ['ICMP Type', redact_icmp_type]
    }
    redact_func_list = []
    help = 'Enter numbers separated by a comma to select the header fields to redact:\n'
    for num, val in redact_func_dict.items():
        field = val[0]
        help += f'\t{num} - {field}\n'
    
    print(help)
    user_input = get_user_input('Enter', None, str, help)
    if user_input == 'all':
        user_input = '1,2,3,4,5,6,7,8,9,10'
    for num in user_input.split(','):
        try:
            num = int(num)
        except ValueError:
            clear_screen()
            red_print('Non number entered...Quitting\n')
            return None
        func = redact_func_dict.get(num, None)
        if func == None:
            continue
        redact_func_list.append(func[1])

    target_file = open(os.path.join(CLEANED_FILEPATH, target_filename), 'r')
    output_file = open(os.path.join(CLEANED_FILEPATH, output_filename), 'w')
    for line in target_file:
        line = line.split()
        timestamp = line[0]
        data = line[1]

        # save the packet class before redacting and put it at the end of the line
        packet_class = get_packet_class(data)

        for func in redact_func_list:
            data = func(data)
        output_file.write(f'{timestamp} {data} {packet_class}\n')
    
    target_file.close()
    output_file.close()

    # clear_screen()
    green_print(f'Redacted data has been outputted to {output_filename}\n')
    input('Press enter to return to the main menu...')
    clear_screen()


def capture_traffic():
    '''Runs tshark command to capture traffic. Stored in the CAPTURES_FILEPATH directory
    Output file named with current timestamp and saved as k12 text file'''
    adapter_names = '' 
    for nice_name in [f'{name.ips[0].nice_name}' for name in ifaddr.get_adapters()]:
        adapter_names += (nice_name + '\n')
    capture_interface_help = f'Enter the name of a valid interface:\n{adapter_names}'
    
    while (capture_interface := get_user_input('Enter the capture interface. Use "help" for help', None, str, capture_interface_help)) not in adapter_names:
        clear_screen()
        red_print('Not a valid adapter name\n')

    capture_filter = get_user_input('Enter a capture filter', '', str, None)

    output_filename = get_user_input('Enter an output filename', 'use timestamp', str)
    if '.' in output_filename:
        output_filename = output_filename[:output_filename.index('.')]
    
    stop_method_help = 'Options:\n\tmanual - stops on user key press\n\tduration:NUM - stop after NUM seconds\n\
    \tpackets:NUM - stop after NUM packets\nExamples: manual, duration:30, packets:100\n'
    stop_method = get_user_input('Enter stop method. Use "help" for help', 'manual', str, stop_method_help)
    manual_stop = False
    if stop_method.startswith('manual'):
        manual_stop = True

    full_path = os.path.join(CAPTURES_FILEPATH, output_filename)

    tshark_command_list = [
        'tshark',
        '-i', capture_interface,
        '-w', f'{full_path}.pcap',
        '-q'
    ]

    if capture_filter:  # add the capture filter if it was specified
        tshark_command_list.insert(3, capture_filter)
        tshark_command_list.insert(3, '-f')

    if not manual_stop:
        tshark_command_list.extend(['-a', stop_method])

    try:
        tshark_process = sp.Popen(tshark_command_list, stdout=sp.PIPE, stderr=sp.PIPE)
    except FileNotFoundError:
        red_print('tshark could not be found. Perhaps it needs to be installed or added to PATH?')
        red_print('Kicking you back to the main menu...\n')
        return
    
    clear_screen()
    green_print('Started capture!')
    print(f'Using command: {" ".join(tshark_command_list)}', end='\n\n')

    time.sleep(1)
    if tshark_process.poll() is not None:  # something went wrong
        err = tshark_process.communicate()[1]
        red_print('Something might have gone wrong with that tshark command.')
        print(err.decode())
        print('Returning to main menu...\n')
        return

    if manual_stop:
        input('Press Enter to stop the capture...')
        yellow_print('Stopping tshark process...')
        tshark_process.terminate()
    tshark_process.wait()
    
    green_print('Capture successfully terminated.')
    
    # convert the file to text
    run_cmd(f'tshark -r {full_path}.pcap -F k12text -w {full_path}.txt')
    os.remove(f'{full_path}.pcap')

    print(f'Capture file is available at {full_path}.txt\n')
    input('Press enter to return to the main menu...')
    clear_screen()
    print()


def clean_captures():
    target_captures_list = []

    get_target_capture_help = 'Enter a valid capture to clean. Enter "all" to clean all captures that have not been cleaned yet.\n'\
    'To clean multiple captures, enter their names separated by a comma.\n\nValid captures:\n'
    get_target_capture_help += ''.join(f'{capture_name}\n' for capture_name in os.listdir(CAPTURES_FILEPATH))
    

    target_captures_input = get_user_input('Enter a capture to clean. Use "help" for help.', 'all', str, get_target_capture_help)
    if target_captures_input == 'all':
        target_captures_list.extend(filename for filename in os.listdir(CAPTURES_FILEPATH) if filename not in os.listdir(CLEANED_FILEPATH))
    else:
        target_captures_list.extend(filename for filename in target_captures_input.split(','))

    clear_screen()
    yellow_print('Cleaning captures...')

    for capture in target_captures_list:
        if not capture.endswith('.txt'):
            capture = capture + '.txt'
        print('\t', end='')
        yellow_print(f'Cleaning {capture}')
        capture_filepath = os.path.join(CAPTURES_FILEPATH, capture)
        output_filepath = os.path.join(CLEANED_FILEPATH, capture)
        
        try:
            capture_file = open(capture_filepath, 'r')
        except FileNotFoundError:
            print('\t', end='')
            red_print(f'The file {capture} could not be found. Skipping...')
            continue
        output_file = open(output_filepath, 'w')

        # the following is for tshark capture files
        # TODO detect if the .txt file is tshark or tcpdump, and add support for cleaning tcpdump captures
        byte_string = None
        prev_line = ''
        while True:
            line = capture_file.readline()
            if not line:
                break
            if not line.startswith('|0'):
                prev_line = line
                continue
            timestamp = prev_line.split()[0]
            
            # if this is the first packet, save the start time for reference
            if byte_string is None:
                start_times = re.split(r':|,', timestamp)
                start_times = [int(num) for num in start_times]

            byte_string = line[6:].replace('|', '')

            this_times = re.split(r':|,', timestamp)
            this_times = [int(num) for num in this_times]
            diff_times = [this_times[i] - start_times[i] for i in range(len(start_times))]

            # get the difference in only microseconds
            microsec_diff = diff_times[0]*3600000000 + diff_times[1]*60000000 + diff_times[2]*1000000 + diff_times[3]*1000 + diff_times[4]
            microsec_diff_string = str(microsec_diff)

            # write to cleaned output file
            output_file.write(f'{microsec_diff_string} {byte_string}')
        
        capture_file.close()
        output_file.close()
        
    green_print('Cleaning finished!')
    print(f'Check {CLEANED_FILEPATH} for the cleaned file(s).')
    input('Press enter to return to the main menu...')
    clear_screen()


def get_capture_data(filename: str):
    total_length = 0
    eth_num = 0
    ip_num = 0
    tcp_num = 0
    udp_num = 0
    num_packets = 0

    eth_type_counts = {}
    ip_proto_counts = {}
    src_mac_counts = {}
    src_ip_counts = {}
    tcp_src_port_counts = {}
    udp_src_port_counts = {}
    tcp_dst_port_counts = {}
    udp_dst_port_counts = {}
    other_type_counts = {}

    microsec_times = []

    capture_file = open(filename, 'r')

    for line in capture_file:
        if not line:
            red_print('Something is wrong with this data. It is possible no data was captured')
            return None

        packet_bytes = line.split()[1]
        microsec_time = line.split()[0]

        microsec_times.append(microsec_time)

        # grab appropriate data from the packet
        packet_length = len(packet_bytes)
        eth_type = get_eth_type(packet_bytes)
        
        # check if eth type is below 0600
        # if so, this is an IEEE 802.3 frame
        if int(eth_type, 16) < 0x0600:
            other_type_counts['STP'] = other_type_counts.setdefault('STP', 0) + 1
            continue
        
        eth_num += 1
        src_mac = get_src_mac(packet_bytes)
        dst_mac = get_dst_mac(packet_bytes)

        mac_string = get_printable_mac(src_mac)
        src_mac_counts[mac_string] = src_mac_counts.setdefault(mac_string, 0) + 1
        
        eth_type_string = ETH_TYPES.get(eth_type, 'Other')
        # add one to the count for this eth_type, if it does not exist create it
        eth_type_counts[eth_type_string] = eth_type_counts.setdefault(eth_type_string, 0) + 1

        if eth_type_string == 'IPv4':
            ip_num += 1
            ip_proto = get_ip_proto(packet_bytes)
            src_ip = get_src_ip(packet_bytes)
            dst_ip = get_dst_ip(packet_bytes)

            ip_string = get_printable_ip(src_ip)
            src_ip_counts[ip_string] = src_ip_counts.setdefault(ip_string, 0) + 1

            ip_proto_string = IP_PROTOS.get(ip_proto, 'Other')
            ip_proto_counts[ip_proto_string] = ip_proto_counts.setdefault(ip_proto_string, 0) + 1
        
        # TCP packet
        if eth_type_string == 'IPv4' and (ip_proto_string == 'TCP' or ip_proto_string == 'UDP'):
            src_port = str(int(get_src_port(packet_bytes), 16))
            dst_port = str(int(get_dst_port(packet_bytes), 16))
            
            if ip_proto_string == 'TCP':
                tcp_num += 1
                tcp_src_port_counts[src_port] = tcp_src_port_counts.setdefault(src_port, 0) + 1
                tcp_dst_port_counts[dst_port] = tcp_dst_port_counts.setdefault(dst_port, 0) + 1



                for port, protocol in TCP_SERVICE_PORTS.items():
                    if src_port == port or dst_port == port:
                        other_type_counts[protocol] = other_type_counts.setdefault(protocol, 0) + 1

            else:  # UDP
                udp_num += 1
                udp_src_port_counts[src_port] = udp_src_port_counts.setdefault(src_port, 0) + 1
                udp_dst_port_counts[dst_port] = udp_dst_port_counts.setdefault(dst_port, 0) + 1

                for port, protocol in UDP_SERVICE_PORTS.items():
                    if src_port == port or dst_port == port:
                        other_type_counts[protocol] = other_type_counts.setdefault(protocol, 0) + 1
                       

        total_length += packet_length
        num_packets += 1

    capture_file.close()

    if not num_packets:  # zero packets in this capture
        red_print('No packets present')
        return None
    
    average_length = total_length / num_packets

    # place all data into the class structure
    # 'sort' the dictionaries contents by key (implementation specific)
    capture_data = CaptureData(
        num_packets=num_packets,
        eth_num=eth_num,
        ip_num=ip_num,
        tcp_num=tcp_num,
        udp_num=udp_num,
        average_length=average_length,
        src_mac_counts=dict(sorted(src_mac_counts.items(), key=lambda item: item[1], reverse=True)),
        dst_mac_counts=None,
        src_ip_counts=dict(sorted(src_ip_counts.items(), key=lambda item: item[1], reverse=True)),
        dst_ip_counts=None,
        eth_type_counts=dict(sorted(eth_type_counts.items(), key=lambda item: item[1], reverse=True)),
        ip_proto_counts=dict(sorted(ip_proto_counts.items(), key=lambda item: item[1], reverse=True)),
        tcp_src_port_counts=dict(sorted(tcp_src_port_counts.items(), key=lambda item: item[1], reverse=True)),
        udp_src_port_counts=dict(sorted(udp_src_port_counts.items(), key=lambda item: item[1], reverse=True)),
        tcp_dst_port_counts=dict(sorted(tcp_dst_port_counts.items(), key=lambda item: item[1], reverse=True)),
        udp_dst_port_counts=dict(sorted(udp_dst_port_counts.items(), key=lambda item: item[1], reverse=True)),
        other_type_counts=dict(sorted(other_type_counts.items(), key=lambda item: item[1])),
        microsec_times=microsec_times
    )

    return capture_data


def analyze_data():
    files = [file for file in os.listdir(CLEANED_FILEPATH)]

    get_file_help = 'Choose from one of the below files to analyze.\nYou can also enter the number corresponding to the file.\n'
    for i, file in enumerate(files):
        get_file_help += ('\t' + str(i) + ' - ' + file + '\n')
    
    while True:
        user_selection = get_user_input('Enter the name or number of the file to analyze. Use "help" for help.', None, str, get_file_help)

        # check if the user is inputting a number
        try:
            user_num_selection = int(user_selection)
            # to execute this code, it must be a number
            if user_num_selection < 0 or user_num_selection >= len(files):
                red_print('That number is out of range.\n')
                continue
            target_file = files[user_num_selection]
            # found a valid file
            break     
        except ValueError:  # not a number. User is entering a file name
            if not user_selection.endswith('.txt'):
                user_selection = user_selection + '.txt'
            if user_selection not in files:
                red_print(f'Could not find the file {user_selection}\n')
                continue
            # found a valid file
            target_file = user_selection
            break

    clear_screen()

    target_file_path = os.path.join(CLEANED_FILEPATH, target_file)
    capture_data = get_capture_data(target_file_path)

    if capture_data is None:
        red_print('No data to analyze')
        input('Press enter to return to the main menu...')
        clear_screen()
        return

    green_print('Analysis complete!')
    print()

    print_text_analysis(capture_data)

    # do matplotlib charts
    # set interactive mode
    plt.ion()

    # make 2x2 figure for displaying four plots
    fig, ax = plt.subplots(nrows=2, ncols=3)
    fig.set_figheight(6)
    fig.set_figwidth(12)
    fig.subplots_adjust(bottom=.25)
    fig.suptitle(f'{target_file} Capture Metrics')
    fig.subplots_adjust(hspace=.8, wspace=.6)

    # 0,0 (Ethernet type)
    this_ax = ax[0,0]
    labels = list(capture_data.eth_type_counts.keys())[:MAX_BAR_CHART_BARS]
    counts = list(capture_data.eth_type_counts.values())[:MAX_BAR_CHART_BARS]
    this_ax.bar(labels, counts)
    this_ax.set_title('Ethernet Type Counts')
    this_ax.set_xlabel('Encapsulated Type')
    this_ax.set_ylabel('Count')

    # 0,1 (IP Proto Types)
    this_ax = ax[0,1]
    labels = list(capture_data.ip_proto_counts.keys())[:MAX_BAR_CHART_BARS]
    counts = list(capture_data.ip_proto_counts.values())[:MAX_BAR_CHART_BARS]
    this_ax.bar(labels, counts)
    this_ax.set_title('IP Protocol Type Counts')
    this_ax.set_xlabel('Encapsulated Type')
    this_ax.set_ylabel('Count')

    # 1,0 (src mac counts)
    this_ax = ax[1,0]
    labels = list(capture_data.src_mac_counts.keys())[:MAX_BAR_CHART_BARS]
    counts = list(capture_data.src_mac_counts.values())[:MAX_BAR_CHART_BARS]
    this_ax.bar(labels, counts)
    this_ax.set_title('Source MAC Counts')
    this_ax.set_xlabel('Source MAC')
    this_ax.set_ylabel('Count')
    this_ax.set_xticks(this_ax.get_xticks(), this_ax.get_xticklabels(), rotation=45, ha='right', rotation_mode='anchor', size=8)

    # 1,1 (src IP counts)
    this_ax = ax[1,1]
    labels = list(capture_data.src_ip_counts.keys())[:MAX_BAR_CHART_BARS]
    counts = list(capture_data.src_ip_counts.values())[:MAX_BAR_CHART_BARS]
    this_ax.bar(labels, counts)
    this_ax.set_title('Source IP Counts')
    this_ax.set_xlabel('Source IP')
    this_ax.set_ylabel('Counts')
    this_ax.set_xticks(this_ax.get_xticks(), this_ax.get_xticklabels(), rotation=45, ha='right', rotation_mode='anchor', size=8)

    # 0,2 (src port counts)
    this_ax = ax[0,2]
    labels = list(capture_data.tcp_src_port_counts.keys())[:MAX_BAR_CHART_BARS]
    counts = list(capture_data.tcp_src_port_counts.values())[:MAX_BAR_CHART_BARS]
    this_ax.bar(labels, counts)
    this_ax.set_title('Source Port Counts')
    this_ax.set_xlabel('Source Port')
    this_ax.set_ylabel('Counts')
    this_ax.set_xticks(this_ax.get_xticks(), this_ax.get_xticklabels(), rotation=45, ha='right', rotation_mode='anchor', size=8)

    # 1,2 (packet times histogram)
    this_ax = ax[1,2]
    data = [int(val)/1000000 for val in capture_data.microsec_times]
    counts, bins, patches = this_ax.hist(data, bins=10)
    this_ax.set_title('Packet Time Histogram')
    this_ax.set_xlabel('Packet Time (s)')
    this_ax.set_ylabel('Frequency')
    this_ax.set_xticks(bins, bins, rotation=45, ha='right', rotation_mode='anchor', size=8)
    this_ax.xaxis.set_major_formatter(FormatStrFormatter('%0.2f'))

    # display the figure
    # fig.show()

    # large histogram
    large_histogram_fig = plt.figure()
    large_histogram_fig.set_figheight(6)
    large_histogram_fig.set_figwidth(12)
    this_ax = large_histogram_fig.add_subplot(1, 1, 1)
    data = [int(val)/1000000 for val in capture_data.microsec_times]
    counts, bins, patches = this_ax.hist(data, bins=50)
    this_ax.set_title('Packet Time Histogram')
    this_ax.set_xlabel('Packet Time (s)')
    this_ax.set_ylabel('Frequency')
    this_ax.set_xticks(bins, bins, rotation=45, ha='right', rotation_mode='anchor', size=8)
    this_ax.xaxis.set_major_formatter(FormatStrFormatter('%0.2f'))
    
    fig.show()
    large_histogram_fig.show()

    green_print('Charts are being displayed...')
    input('Press enter to clear charts and return to the main menu...')
    
    # close figures
    plt.close(fig)
    plt.close(large_histogram_fig)
    
    clear_screen()
    print()


def print_counts_dict(counts_dict: dict):
    if len(counts_dict) == 0:
        print('No data collected for this statistic')
        return
    extra_values = 0
    for i, (mac, count) in enumerate(counts_dict.items()):
        if i < MAX_BAR_CHART_BARS:
            print(f'{mac:.<40}{count}')
        else:
            extra_values += 1
    if extra_values:
        print(f'{extra_values} more values not shown')


def print_text_analysis(capture_data: CaptureData) -> None:
    print('Overall Counts:')
    print(f'{"Average Length:":.<40}{capture_data.average_length:.2f}')
    print(f'{"Total number of packets:":.<40}{capture_data.num_packets}')
    print(f'{"Total Ethernet II packets:":.<40}{capture_data.eth_num}')
    print(f'{"Total IP packets:":.<40}{capture_data.ip_num}')
    print(f'{"Total TCP packets:":.<40}{capture_data.tcp_num}')
    print()

    print('Ethernet Type Counts:')
    print_counts_dict(capture_data.eth_type_counts)
    print()

    print('IP Protocol Counts')
    print_counts_dict(capture_data.ip_proto_counts)
    print()

    print('Source MAC Counts:')
    print_counts_dict(capture_data.src_mac_counts)
    print()

    # print('Destination MAC Counts:')
    # print_counts_dict(capture_data.dst_mac_counts)
    # print()

    print('Source IP Counts:')
    print_counts_dict(capture_data.src_ip_counts)
    print()

    # print('Destination IP Counts:')
    # print_counts_dict(capture_data.dst_ip_counts)
    # print()

    print('TCP Source Port Counts:')
    print_counts_dict(capture_data.tcp_src_port_counts)
    print()

    print('Other types')
    print_counts_dict(capture_data.other_type_counts)
    print()


# returns a list of packet layers corresponding to PACKET_LAYERS enum
# used for checking whether data at specific locations should be redacted
def get_packet_layers(packet_bytes: str) -> list[int]:
    layers = []
    # for right now, just assume everything is ethernet
    layers.append(PACKET_LAYERS.ETHERNET)

    if ETH_TYPES.get(get_eth_type(packet_bytes)) == 'ARP':
        layers.append(PACKET_LAYERS.ARP)
    elif ETH_TYPES.get(get_eth_type(packet_bytes)) == 'IPv4':
        layers.append(PACKET_LAYERS.IPV4)
        if IP_PROTOS.get(get_ip_proto(packet_bytes)) == 'ICMP':
            layers.append(PACKET_LAYERS.ICMP)
        if IP_PROTOS.get(get_ip_proto(packet_bytes)) == 'TCP':
            layers.append(PACKET_LAYERS.TCP)
        elif IP_PROTOS.get(get_ip_proto(packet_bytes)) == 'UDP':
            layers.append(PACKET_LAYERS.UDP)
    else:
        layers.append(PACKET_LAYERS.IPV6)

    return layers


# returns packet class - our class are [ARP Request, ARP Reply, ICMP Echo Request, ICMP Echo Reply, TLS, HTTP, DNS, QUIC, Other]
# this function returns [0, 1, 2, 3, 4, 5, 6, 7, 8] corresponding to each class
def get_packet_class(packet_bytes: str) -> int:
    other = CLASSES.get('Other')
    if not other:
        red_print('No "Other" value present in classes!\n')
        return -1
    if ETH_TYPES.get(get_eth_type(packet_bytes)) == 'ARP':  # ARP - is it reply or request
        return CLASSES.get(ARP_OPCODES.get(get_arp_opcode(packet_bytes), 'Other'), other)
    elif ETH_TYPES.get(get_eth_type(packet_bytes)) == 'IPv4':  # IPv4
        if IP_PROTOS.get(get_ip_proto(packet_bytes)) == 'ICMP':  # ICMP - echo reply or request
            return CLASSES.get(ICMP_TYPES.get(get_icmp_type(packet_bytes), 'Other'), other)
        elif IP_PROTOS.get(get_ip_proto(packet_bytes)) == 'TCP':  # TCP
            src_port_class = CLASSES.get(TCP_SERVICE_PORTS.get(get_src_port(packet_bytes), 'Other'), other)
            return src_port_class if src_port_class != other else CLASSES.get(TCP_SERVICE_PORTS.get(get_dst_port(packet_bytes)), other)
        elif IP_PROTOS.get(get_ip_proto(packet_bytes)) == 'UDP':  # UDP
            src_port_class = CLASSES.get(UDP_SERVICE_PORTS.get(get_src_port(packet_bytes), 'Other'), other)
            return src_port_class if src_port_class != other else CLASSES.get(UDP_SERVICE_PORTS.get(get_dst_port(packet_bytes)), other)
        else:  # neither TCP nor UDP
            return other
    else:  # IPv6 or something else
        return other


def extract_features():
    files = [file for file in os.listdir(CLEANED_FILEPATH)]
    get_file_help = 'Choose one of the below files from which to extract features.\nYou can also enter the number corresponding to each file.\n'
    for i, file in enumerate(files):
        get_file_help += ('\t' + str(i) + ' - ' + file + '\n')
    
    # get input file
    while True:
        user_selection = get_user_input('Enter the name or number of the file to analyze. Use "help" for help.', None, str, get_file_help)

        # check if the user is inputting a number
        try:
            user_num_selection = int(user_selection)
            # to execute this code, it must be a number
            if user_num_selection < 0 or user_num_selection >= len(files):
                red_print('That number is out of range.\n')
                continue
            target_filename = files[user_num_selection]
            # found a valid file
            break     
        except ValueError:  # not a number. User is entering a file name
            if not user_selection.endswith('.txt'):
                user_selection = user_selection + '.txt'
            if user_selection not in files:
                red_print(f'Could not find the file {user_selection}\n')
                continue
            # found a valid file
            target_filename = user_selection
            break
    
    target_file_path = os.path.join(CLEANED_FILEPATH, target_filename)

    # get output file
    while True:
        out_filename = get_user_input('Enter the relative path for the output file (.npy) file.', 'out.npy', str, None)
        
        out_filename.rstrip(os.path.sep)
        if not out_filename.endswith('.npy'):
            out_filename = f'{out_filename}.npy'

        y_output_filename = out_filename.split('.')[0] + '_y.npy'

        try:
            if os.path.exists(out_filename) or os.path.exists(y_output_filename):
                raise FileExistsError()
            open(out_filename, 'a').close()
            break
        except FileNotFoundError:
            clear_screen()
            red_print(f'The path {os.path.normpath(out_filename)} could not be found\n')
        except PermissionError:
            clear_screen()
            red_print('You do not have permission to write to that file.\n')
        except FileExistsError:
            clear_screen()
            red_print('That output file already exists.\n')
        except Exception as e:
            clear_screen()
            red_print(f'An error occurred with that file :( \n{e}\n')
    
    clear_screen()

    # Initialize X, y and q
    # y holds our classes [ARP Request, ARP Reply, ICMP Echo Request, ICMP Echo Reply, TLS, HTTP, DNS, QUIC, Other]
    # they map to [0, 1, 2, 3, 4, 5, 6, 7, 8]
    y = []
    X = []

    # Initialize counters
    packets_analyzed = 0
    samples_per_class = dict((packet_class, 0) for packet_class in CLASSES.values())
    features_extracted = 0
    with open(target_file_path, 'r') as target_file, open(out_filename, 'ab') as out_file:
        # Create a list of nibbles for each packet in target_file
        for line in target_file:
            line_list = line.split()
            packet_bytes = line_list[1]
            if len(line_list) == 2:  # not redacted data, no class identifier added
                packet_class = get_packet_class(packet_bytes)
            elif len(line_list) == 3:  # is redacted data and identifier was added
                packet_class = int(line_list[2])
            else:
                packet_class = -1

            if packet_class == -1:
                return
            if not samples_per_class[packet_class] < SAMPLES_PER_CLASS:
                continue
            
            # Increment count and add to y
            samples_per_class[packet_class] += 1
            y.append(packet_class)

            # Create X and convert each hex to int value
            nibbles = [int(let, 16) for let in packet_bytes[:NUM_FEATURES]]
            # pad to NUM_FEATURES length
            if len(nibbles) < NUM_FEATURES:
                nibbles.extend([0] * (NUM_FEATURES-len(nibbles)))
            
            # increment counts
            features_extracted += len(nibbles)
            packets_analyzed += 1

            # Convert to a ndarray and pickle to out file
            X.append(nibbles)
    
    # convert x and y to ndarrays
    y_arr = np.array(y, dtype=int)
    X_arr = np.array(X, dtype=int)

    # save both X and y to files
    np.save(y_output_filename, y_arr)
    np.save(out_filename, X_arr)

    print('Packet class counts:')
    not_enough_packets_warning = False
    for packet_class, count in samples_per_class.items():
        if count == 0:
            continue
        print(f'{dict(zip(CLASSES.values(), CLASSES.keys())).get(packet_class):.<40}{count}')
        if count < SAMPLES_PER_CLASS:
            not_enough_packets_warning = True
    print()
    if not_enough_packets_warning:
        yellow_print(f'WARNING: One or more classes do not have enough packets ({SAMPLES_PER_CLASS})!\n')

    green_print(f'Data from {target_filename} successfully saved to {out_filename}')
    green_print(f'Targets have been saved to {y_output_filename}')
    green_print(f'Analyzed {features_extracted} features from {packets_analyzed} packets!')
    input('\nPress enter to return to the main menu...')
    clear_screen()


def main():
    # get the operating system
    global os_name
    os_name = platform.system()
    if os_name == 'Windows' or os_name == 'Linux':
        green_print(f'Detected running on {os_name} system!')
    else:
        red_print(f'Detected running on {os_name} system which is not supported.')
        exit()
    
    # check that captures and cleaned file paths exist
    if not os.path.exists(CAPTURES_FILEPATH):
        red_print(f'The path for capture files "{CAPTURES_FILEPATH}" does not exist. Qutting...')
        exit()
    if not os.path.exists(CLEANED_FILEPATH):
        red_print(f'The path for cleaned files "{CLEANED_FILEPATH}" does not exist. Quitting...')
        exit()

    while True:
        print_menu()
        try:
            user_input = int(input('Select an option: ').strip())
        except ValueError:
            clear_screen()
            red_print('Please enter a valid number\n')
            continue
        except KeyboardInterrupt:
            print('Goodbye!\n')
            exit()

        if user_input == 1:
            capture_traffic()
        elif user_input == 2:
            clean_captures()
        elif user_input == 3:
            analyze_data()
        elif user_input == 4:
            extract_features()
        elif user_input == 5:
            redact_data()
        else:
            clear_screen()
            red_print('Enter the number for a valid option\n')


if __name__ == '__main__':
   main()
    
