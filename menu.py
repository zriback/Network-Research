"""
This file is a menu program with the following capabilities as they relate to network data capture
and machine learning
- Network traffic capture
- Clean captures
- Analyze data
- Redact data
- Extract features
- Extract 2D features
- Combine cleaned captures
"""

import sys
import os
import subprocess as sp
import time
import re
from functools import partial
import platform
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import matplotlib.pyplot as plt
from matplotlib.ticker import FormatStrFormatter
import numpy as np
import ifaddr
from typing import Callable, Any

# "Linux" or "Windows"
OS_NAME = platform.system()

class PacketLayers(Enum):
    """
    Enum containing all layers we are interested in
    """
    ETHERNET = 1
    IPV4 = 2
    IPV6 = 3
    ARP = 4
    ICMP = 5
    TCP = 6
    UDP = 7
    HTTP = 8
    DNS = 9


@dataclass
class CaptureData:
    """
    Dataclass containing all interesting information about a network packet capture
    """
    num_packets: int = 0
    eth_num: int = 0
    ip_num: int = 0
    tcp_num: int = 0
    udp_num: int = 0
    average_length: float = 0
    src_mac_counts: Optional[dict] = None
    dst_mac_counts: Optional[dict] = None
    src_ip_counts: Optional[dict] = None
    dst_ip_counts: Optional[dict] = None
    eth_type_counts: Optional[dict] = None
    ip_proto_counts: Optional[dict] = None
    tcp_src_port_counts: Optional[dict] = None
    tcp_dst_port_counts: Optional[dict] = None
    udp_src_port_counts: Optional[dict] = None
    udp_dst_port_counts: Optional[dict] = None
    other_type_counts: Optional[dict] = None
    microsec_times: list = field(default_factory=list)

@dataclass(frozen=True)
class Conversation:
    """
    Dataclass for storing and tracking different conversations in a capture
    """
    src_addr: str
    dst_addr: str
    src_port: str
    dst_port: str
    protocol: Enum

    def __eq__(self, other):
        if type(other) != Conversation:
            return False
        return self.protocol == other.protocol and \
            {self.src_addr, self.dst_addr} == {other.src_addr, other.dst_addr} and \
            {self.src_port, self.dst_port} == {other.src_port, other.dst_port}
    
    def __hash__(self):
        return hash((self.protocol, frozenset((self.src_addr, self.dst_addr)), frozenset((self.src_port, self.dst_port))))

# File paths for directories containing raw captures, cleaned files, and for output files
CAPTURES_FILEPATH = 'captures'
CLEANED_FILEPATH = 'cleaned'
OUTPUT_FILEPATH = 'output'

TRAINED_WEIGHTS_FILEPATH = 'params.pth'

# Number of nibbles to extract from each packet as a feature from each packet
# The first NUM_FEATURES/2 bytes are extracted from each packet
NUM_FEATURES = 128
NIBBLES_PER_FEATURE = 1
CNN_FEATURES_DIMENSION = 14
MAX_CONVERSATION_LENGTH = 25
MIN_CONVERSATION_LENGTH = 1

SAMPLES_PER_CLASS = 1000

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
SRC_IPV6_LOC = 22
DST_IPV6_LOC = 38
IP_PROTO_LOC = 23
IPV6_NEXT_HEADER_LOC = 20
SRC_PORT_LOC = 34
DST_PORT_LOC = 36
ARP_OPCODE_LOC = 20
ICMP_TYPE_LOC = 34
LLC_DSAP_LOC = 14
LLC_SSAP_LOC = 15
LLC_CONTROL_FIELD_LOC = 16
IPV6_HOP_BY_HOP_NEXT_HEADER_LOC = 54

ETH_802_3_THRESHOLD = 1500

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

IPV6_NEXT_HEADERS = {
    '11' : 'UDP',
    '00' : 'hop-by-hop',
    '3a' : 'ICMPv6'
}

LLC_DSAP = {
    '42' : 'STP'
}

IPV6_HOP_BY_HOP_NEXT_HEADERS = {
    '3a' : 'ICMPv6'
}

TCP_SERVICE_PORTS = {
    '0050' : 'HTTP',
    '1f90' : 'HTTP-8080',
    '01bb' : 'TLS'
}

UDP_SERVICE_PORTS = {
    '0035' : 'DNS',
    '0043' : 'DHCP',
    '0044' : 'DHCP',
    '0089' : 'NBNS',
    '076c' : 'SSDP',
    '07c6' : 'SSDP',
    '01bb' : 'QUIC',
    '14e9' : 'MDNS'
}

ARP_OPCODES = {
    '0001' : 'ARP Request',
    '0002' : 'ARP Reply'
}

ICMP_TYPES = {
    '00' : 'ICMP Echo Reply',
    '08' : 'ICMP Echo Request'
}

# Defines the classes that we care about
# There must be an "other" class, but if it is defined as -1, it means we do not care about it
CLASSES = {
    'ARP Request': 0,
    'ARP Reply' : 1,
    'ICMP Echo Request' : 2,
    'ICMP Echo Reply' : 3,
    'ICMPv6' : 4,
    'TLS' : 5,
    'HTTP' : 6,
    'DNS-query' : 7,
    'DNS-response': 8,
    'QUIC' : 9,
    'MDNS' : 10,
    'NBNS' : 11,
    'SSDP' : 12,
    'STP' : 13,
    'Other' : -1
}

CONVERSATION_CLASSES = {
    PacketLayers.TCP
}

def green_print(msg: str) -> None:
    """Convenient function for printing green text"""
    print(GREEN_COLOR + msg + DEFAULT_COLOR)

def red_print(msg: str) -> None:
    """Convenient function for printing red text"""
    print(RED_COLOR + msg + DEFAULT_COLOR)

def yellow_print(msg: str) -> None:
    """Convenient function for printing yellow text"""
    print(YELLOW_COLOR + msg + DEFAULT_COLOR)

def get_last_line(filename: str) -> str:
    """Convenient function for returning the last line of a file efficiently"""
    last_line = 0
    with open(filename, 'rb') as f:
        try:  # catch OSError in case of a one line file 
            f.seek(-2, os.SEEK_END)
            while f.read(1) != b'\n':
                f.seek(-2, os.SEEK_CUR)
        except OSError:
            f.seek(0)
        last_line = f.readline().decode().strip()
    return last_line

def get_printable_ip(ip: str) -> str | None:
    """Convenient function for getting printable IP address from hex bytes"""
    if len(ip) != 4*2:
        return None
    return '.'.join(str(int(''.join(pair), 16)) for pair in zip(*[iter(ip)]*2))

def get_printable_mac(mac: str) -> str | None:
    """Convenient function for getting printable MAC address from hex bytes"""
    if len(mac) != 6*2:
        return None
    return ':'.join(''.join(pair) for pair in zip(*[iter(mac)]*2))

def get_header_field(data: str, loc: int, length: int, offset: int = 0) -> str:
    """Gets bytes of specified length from specified location from the data"""
    loc += offset
    return data[loc*2:(loc+length)*2]

# Partial functions for getting each header field
get_src_mac = partial(get_header_field, loc=SRC_MAC_LOC, length=6)
get_dst_mac = partial(get_header_field, loc=DST_MAC_LOC, length=6)
get_src_ip = partial(get_header_field, loc=SRC_IP_LOC, length=4)
get_dst_ip = partial(get_header_field, loc=DST_IP_LOC, length=4)
get_src_ipv6 = partial(get_header_field, loc=SRC_IPV6_LOC, length=16)
get_dst_ipv6 = partial(get_header_field, loc=DST_IPV6_LOC, length=16)
get_eth_type = partial(get_header_field, loc=ETH_TYPE_LOC, length=2)
get_ip_proto = partial(get_header_field, loc=IP_PROTO_LOC, length=1)
get_ipv6_proto = partial(get_header_field, loc=IPV6_NEXT_HEADER_LOC, length=1)
get_src_port = partial(get_header_field, loc=SRC_PORT_LOC, length=2)
get_dst_port = partial(get_header_field, loc=DST_PORT_LOC, length=2)
get_arp_opcode = partial(get_header_field, loc=ARP_OPCODE_LOC, length=2)
get_icmp_type = partial(get_header_field, loc=ICMP_TYPE_LOC, length=1)
get_llc_dsap = partial(get_header_field, loc=LLC_DSAP_LOC, length=1)
get_llc_ssap = partial(get_header_field, loc=LLC_SSAP_LOC, length=1)
get_llc_control_field = partial(get_header_field, loc=LLC_CONTROL_FIELD_LOC, length=1)
get_ipv6_hop_by_hop_next_header = partial(get_header_field, loc=IPV6_HOP_BY_HOP_NEXT_HEADER_LOC, length=1)


def redact_packet_data(data: str, loc: int, length: int, required_layers: list[PacketLayers]):
    """Convenient function for replacing specified bytes with zeros"""
    if any(layer in get_packet_layers(data) for layer in required_layers) and (loc+length)*2 <= len(data):
        return data[:loc*2] + '0'*length*2 + data[(loc+length)*2:]
    else:
        return data

# Partial functions for redacting each header field
redact_src_mac = partial(redact_packet_data, loc=SRC_MAC_LOC, length=6, required_layers=[PacketLayers.ETHERNET])
redact_dst_mac = partial(redact_packet_data, loc=DST_MAC_LOC, length=6, required_layers=[PacketLayers.ETHERNET])
redact_src_ip = partial(redact_packet_data, loc=SRC_IP_LOC, length=4, required_layers=[PacketLayers.IPV4])
redact_dst_ip = partial(redact_packet_data, loc=DST_IP_LOC, length=4, required_layers=[PacketLayers.IPV4])
redact_eth_type = partial(redact_packet_data, loc=ETH_TYPE_LOC, length=2, required_layers=[PacketLayers.ETHERNET])
redact_ip_proto = partial(redact_packet_data, loc=IP_PROTO_LOC, length=1, required_layers=[PacketLayers.IPV4])
redact_ipv6_proto = partial(redact_packet_data, loc=IPV6_NEXT_HEADER_LOC, length=1, required_layers=[PacketLayers.IPV6])
redact_src_port = partial(redact_packet_data, loc=SRC_PORT_LOC, length=2, required_layers=[PacketLayers.TCP, PacketLayers.UDP])
redact_dst_port = partial(redact_packet_data, loc=DST_PORT_LOC, length=2, required_layers=[PacketLayers.TCP, PacketLayers.UDP])
redact_arp_opcode = partial(redact_packet_data, loc=ARP_OPCODE_LOC, length=2, required_layers=[PacketLayers.ARP])
redact_icmp_type = partial(redact_packet_data, loc=ICMP_TYPE_LOC, length=1, required_layers=[PacketLayers.ICMP])


def clear_screen():
    """Wrapper function for clearing the screen"""
    if OS_NAME == 'Windows':
        os.system('cls')
    else:  # 'Linux'
        os.system('clear')


def run_cmd(command: str) -> bytes:
    """Runs the given command. Returns the output"""
    command_process = sp.Popen(command.split(), stdout=sp.PIPE, stderr=sp.PIPE)
    output = command_process.communicate()[0]
    return output


def print_menu():
    """Prints all menu options"""
    output = 'Select an option:\n'
    output += '\t(1) Capture Traffic\n'
    output += '\t(2) Clean Captures\n'
    output += '\t(3) Analyze Data\n'
    output += '\t(4) Analyze Time Series Data\n'
    output += '\t(5) Extract Features\n'
    output += '\t(6) Extract 2D Features\n'
    output += '\t(7) Extract Conversations\n'
    output += '\t(8) Combine Cleaned Captures\n'
    output += '\t(9) Test Trained Model'
    print(output)


def get_user_input(message: str, default: str | None, use_type: type, help_msg=None, test_func: None | Callable[[Any], bool] = None):
    """
    Get and returns user input

    Args:
        message (str): Prompt to give to the user
        default (str): Default value to use if the user does not enter anything
        use_type (type): Type to verify the user enters
        help_message (str): Help message to give the user if they type 'help'
        test_func (Callable): Test function that returns true/false that the value is valid. Used for adding more checks to ensure valid values
    Returns:
        The valid user input
    """
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
        elif user_input == 'help' and help_msg is not None:
            clear_screen()
            print(help_msg)
            continue
        else:
            try:
                user_input = use_type(user_input)
                # run test function
                if test_func is not None and not test_func(user_input):
                    raise ValueError()
            except ValueError:
                clear_screen()
                red_print('Enter a valid value\n')
                continue
        break
    print()
    return user_input


def get_new_file(message: str, default: str, location: str | None = None) -> str:
    """
    Helper method for getting the name of a new file from the user

    Args:
        message (str): prompt to give to the user
        default (str): default value if the user does not enter anything
        location (str): Location where the file will be located. None means the current working directory
    Returns:
        str: The name of the file
    """
    extension = '.' + default.split('.')[-1]
    while True:
        out_filename = get_user_input(message, default, str, None)

        out_filename.rstrip(os.path.sep)
        if not out_filename.endswith(extension):
            out_filename = f'{out_filename}{extension}'

        if location:
            out_filename = os.path.join(location, out_filename)
        try:
            if os.path.exists(out_filename):
                raise FileExistsError()
            open(out_filename, 'a', encoding='utf-8').close()
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
        except OSError as e:
            clear_screen()
            red_print(f'An error occurred with that file :( \n{e}\n')

    clear_screen()
    return out_filename


def get_existing_file(message: str, default: str | None, location: str) -> str:
    """
    Helper function for getting the name of an already existing file from the user

    Args:
        message (str): prompt to give to the user
        default (str): default value if the user does not enter anything
        location (str): the location where this file exists
    Returns:
        str: The target file path
    """
    files = os.listdir(location)
    get_file_help = 'Choose one of the below files.\nYou can also enter the number corresponding to each file.\n'
    for i, file in enumerate(files):
        get_file_help += ('\t' + str(i) + ' - ' + file + '\n')

    while True:
        user_selection = get_user_input(message, default, str, get_file_help)

        # check if the user is inputting a number
        try:
            user_num_selection = int(user_selection)
            # to execute this code, it must be a number
            if user_num_selection < 0 or user_num_selection >= len(files):
                clear_screen()
                red_print('That number is out of range.\n')
                continue
            target_filename = files[user_num_selection]
            # found a valid file
            break
        except ValueError:  # not a number. User is entering a file name
            if not user_selection.endswith('.txt'):
                user_selection = user_selection + '.txt'
            if user_selection not in files:
                clear_screen()
                red_print(f'Could not find the file {user_selection}\n')
                continue
            # found a valid file
            target_filename = user_selection
            break

    target_file_path = os.path.join(location, target_filename)
    return target_file_path


def get_redact_functions() -> list[partial]:
    """Help to get list of partial functions used for redacting certain header info based on user input"""
    def _input_validator(input: str) -> bool:
        """Helper function to validate user input"""
        if input == 'all':
            return True
        for digit_str in input.strip().split(','):
            try:
                int(digit_str)
            except ValueError:
                return False
        return True
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
    help_msg = 'Enter numbers separated by a comma to select the header fields to redact:\n'
    for num, val in redact_func_dict.items():
        help_msg += f'\t{num} - {val[0]}\n'

    print(help_msg)
    user_input = get_user_input('Enter. Use "help" for help.', '', str, help_msg, test_func=_input_validator)
    if user_input == 'all':
        user_input = ','.join(str(index) for index in redact_func_dict)
    if user_input == '':
        return []
    for num in user_input.split(','):  # _input_validator already ensures the input was valid
        func = redact_func_dict.get(int(num), None)
        if func is None:
            continue
        redact_func_list.append(func[1])
    return redact_func_list


def capture_traffic():
    """Runs tshark command to capture traffic. Stored in the CAPTURES_FILEPATH directory
    Output file named with current timestamp and saved as k12 text file"""
    adapter_names = ''
    for nice_name in [f'{name.ips[0].nice_name}' for name in ifaddr.get_adapters()]:
        adapter_names += (nice_name + '\n')
    capture_interface_help = f'Enter the name of a valid interface:\n{adapter_names}'

    while (capture_interface := get_user_input('Enter the capture interface. Use "help" for help', None, str, capture_interface_help)) \
        not in adapter_names:
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
        clear_screen()
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


def combine_cleaned_captures():
    """Combines two cleaned captures into one file for easier analysis and feature extraction"""
    while True:
        first_file = get_existing_file('Enter the first file. Use "help" for help', None, CLEANED_FILEPATH)
        second_file = get_existing_file('Enter the second file. Use "help" for help', None, CLEANED_FILEPATH)
        if first_file == second_file:
            clear_screen()
            red_print('The two files cannot be the same!\n')
            continue
        # Might want to put a check here to see if only one has been redacted
        break

    output_file = get_new_file('Enter an output file name', 'combined.txt', CLEANED_FILEPATH)

    with open(first_file, 'r', encoding='utf-8') as first, \
        open(second_file, 'r', encoding='utf-8') as second, \
        open(output_file, 'w', encoding='utf-8') as out:
        first_lines_count = 0
        second_lines_count = 0
        for line in first:
            out.write(line)
            first_lines_count += 1
        for line in second:
            out.write(line)
            second_lines_count += 1
    green_print(f'Read {first_lines_count} packets from {first_file}')
    green_print(f'Read {second_lines_count} packets from {second_file}')
    green_print(f'Wrote {first_lines_count+second_lines_count} packets to {output_file}')
    input('Press enter to return to the main menu...')
    clear_screen()


def clean_captures():
    """Clean captures """
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
            # this is a pcap file that we should make into a k12 text first (if the k12 does not already exist)
            if (capture.endswith('.pcapng') or capture.endswith('.pcap')):
                old_capture_name = capture
                capture = f'{os.path.splitext(capture)[0]}.txt'  # it either already exists or we are going to create it
                if not os.path.exists(os.path.join(CAPTURES_FILEPATH, capture)):
                    yellow_print('\tDetected pcap/pcapng file. Converting to k12text...')
                    run_cmd(f'tshark -r {os.path.join(CAPTURES_FILEPATH, old_capture_name)} -F k12text -w {os.path.join(CAPTURES_FILEPATH, capture)}')
            else:
                capture = capture + '.txt'
        print('\t', end='')
        yellow_print(f'Cleaning {capture}')
        capture_filepath = os.path.join(CAPTURES_FILEPATH, capture)
        output_filepath = os.path.join(CLEANED_FILEPATH, capture)

        if os.path.exists(output_filepath):
            yellow_print('\tFile has already been cleaned. Skipping...')
            continue

        try:
            capture_file = open(capture_filepath, 'r', encoding='utf-8')
        except FileNotFoundError:
            print('\t', end='')
            red_print(f'The file {capture} could not be found. Skipping...')
            continue
        output_file = open(output_filepath, 'w', encoding='utf-8')

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


def get_capture_data(filename: str) -> CaptureData | None:
    """Extract capture data from the specified cleaned file"""
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

    capture_file = open(filename, 'r', encoding='utf-8')

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
        #dst_mac = get_dst_mac(packet_bytes)

        mac_string = get_printable_mac(src_mac)
        src_mac_counts[mac_string] = src_mac_counts.setdefault(mac_string, 0) + 1

        eth_type_string = ETH_TYPES.get(eth_type, 'Other')
        # add one to the count for this eth_type, if it does not exist create it
        eth_type_counts[eth_type_string] = eth_type_counts.setdefault(eth_type_string, 0) + 1

        if eth_type_string == 'IPv4':
            ip_num += 1
            ip_proto = get_ip_proto(packet_bytes)
            src_ip = get_src_ip(packet_bytes)
            #dst_ip = get_dst_ip(packet_bytes)

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
    """Calculates statistics and creates plots to visualize capture data"""
    target_file_path = get_existing_file('Enter the name or number of the file to analyze. Use "help" for help', None, CLEANED_FILEPATH)
    target_file = os.path.basename(target_file_path)
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

    # make 2x3 figure for displaying four plots
    fig, ax = plt.subplots(nrows=2, ncols=3)
    fig.set_figheight(6)
    fig.set_figwidth(12)
    fig.subplots_adjust(bottom=.25)
    fig.suptitle(f'{target_file} Capture Metrics')
    fig.subplots_adjust(hspace=.8, wspace=.6)

    # 0,0 (Ethernet type)
    this_ax = ax[0,0]
    if capture_data.eth_type_counts is not None:
        labels = list(capture_data.eth_type_counts.keys())[:MAX_BAR_CHART_BARS]
        counts = list(capture_data.eth_type_counts.values())[:MAX_BAR_CHART_BARS]
    else:
        labels = []
        counts = []
    this_ax.bar(labels, counts)
    this_ax.set_title('Ethernet Type Counts')
    this_ax.set_xlabel('Encapsulated Type')
    this_ax.set_ylabel('Count')

    # 0,1 (IP Proto Types)
    this_ax = ax[0,1]
    if capture_data.ip_proto_counts is not None:
        labels = list(capture_data.ip_proto_counts.keys())[:MAX_BAR_CHART_BARS]
        counts = list(capture_data.ip_proto_counts.values())[:MAX_BAR_CHART_BARS]
    else:
        labels = []
        counts = []
    this_ax.bar(labels, counts)
    this_ax.set_title('IP Protocol Type Counts')
    this_ax.set_xlabel('Encapsulated Type')
    this_ax.set_ylabel('Count')

    # 1,0 (src mac counts)
    this_ax = ax[1,0]
    if capture_data.src_mac_counts is not None:
        labels = list(capture_data.src_mac_counts.keys())[:MAX_BAR_CHART_BARS]
        counts = list(capture_data.src_mac_counts.values())[:MAX_BAR_CHART_BARS]
    else:
        labels = []
        counts = []
    this_ax.bar(labels, counts)
    this_ax.set_title('Source MAC Counts')
    this_ax.set_xlabel('Source MAC')
    this_ax.set_ylabel('Count')
    this_ax.set_xticks(this_ax.get_xticks(), this_ax.get_xticklabels(), rotation=45, ha='right', rotation_mode='anchor', size=8)

    # 1,1 (src IP counts)
    this_ax = ax[1,1]
    if capture_data.src_ip_counts is not None:
        labels = list(capture_data.src_ip_counts.keys())[:MAX_BAR_CHART_BARS]
        counts = list(capture_data.src_ip_counts.values())[:MAX_BAR_CHART_BARS]
    else:
        labels = []
        counts = []
    this_ax.bar(labels, counts)
    this_ax.set_title('Source IP Counts')
    this_ax.set_xlabel('Source IP')
    this_ax.set_ylabel('Counts')
    this_ax.set_xticks(this_ax.get_xticks(), this_ax.get_xticklabels(), rotation=45, ha='right', rotation_mode='anchor', size=8)

    # 0,2 (src port counts)
    this_ax = ax[0,2]
    if capture_data.tcp_src_port_counts is not None:
        labels = list(capture_data.tcp_src_port_counts.keys())[:MAX_BAR_CHART_BARS]
        counts = list(capture_data.tcp_src_port_counts.values())[:MAX_BAR_CHART_BARS]
    else:
        labels = []
        counts = []
    this_ax.bar(labels, counts)
    this_ax.set_title('Source Port Counts')
    this_ax.set_xlabel('Source Port')
    this_ax.set_ylabel('Counts')
    this_ax.set_xticks(this_ax.get_xticks(), this_ax.get_xticklabels(), rotation=45, ha='right', rotation_mode='anchor', size=8)

    # 1,2 (packet times histogram)
    this_ax = ax[1,2]
    data = [int(val)/1000000 for val in capture_data.microsec_times]
    counts, bins = this_ax.hist(data, bins=10)[:2]
    this_ax.set_title('Packet Time Histogram')
    this_ax.set_xlabel('Packet Time (s)')
    this_ax.set_ylabel('Frequency')
    this_ax.set_xticks(bins, bins, rotation=45, ha='right', rotation_mode='anchor', size=8)
    this_ax.xaxis.set_major_formatter(FormatStrFormatter('%0.2f'))

    # large histogram
    large_histogram_fig = plt.figure()
    large_histogram_fig.set_figheight(6)
    large_histogram_fig.set_figwidth(12)
    this_ax = large_histogram_fig.add_subplot(1, 1, 1)
    data = [int(val)/1000000 for val in capture_data.microsec_times]
    counts, bins = this_ax.hist(data, bins=50)[:2]
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


def extract_time_series_data(target_file_path: str, time_divisions: int) -> tuple[list[dict[int, int]], list[float]]:
    last_micro_time = int(get_last_line(target_file_path).split()[0])

    buckets: list[dict[int, int]] = [{packet_class_int:0 for packet_class_int in CLASSES.values()} for _ in range(time_divisions)]
    bucket_cutoffs: list[float] = [i*(last_micro_time/time_divisions) for i in range(time_divisions)]

    with open(target_file_path, 'r') as f:
        for line in f:
            line_list = line.split()
            micro_time = int(line_list[0].strip())
            packet_bytes = line_list[1].strip()
            bucket_index = int(micro_time//(last_micro_time/time_divisions))
            if bucket_index == time_divisions:  # the very last packet will otherwise get an index that is one two high
                bucket_index -= 1
            packet_class_int = get_packet_class(packet_bytes, CLASSES)
            buckets[bucket_index][packet_class_int] = buckets[bucket_index].get(packet_class_int, 0) + 1
    return buckets, bucket_cutoffs


def time_series_analysis():
    """Makes a graph to analysis the presence of classes over time in a dataset"""
    target_file_path = get_existing_file('Enter the file you would like to analyze', None, CLEANED_FILEPATH)
    target_file = os.path.basename(target_file_path)

    # the number of buckets to split the packets into
    time_divisions = 100
    
    time_series_data, bucket_cuttoffs = extract_time_series_data(target_file_path, time_divisions)
    # turn bucket_cuttoffs to be in seconds instead of microseconds
    bucket_cuttoffs = [i/1e6 for i in bucket_cuttoffs]

    # do matplot charts
    # set interactive mode
    plt.ion()
    fig = plt.figure()
    fig.set_figheight(9)
    fig.set_figwidth(18)
    ax = fig.add_subplot(1, 1, 1)
    ax.set_title('Packet Classes Over Time')
    ax.set_xlabel('Packet Time (s)')
    ax.set_ylabel('Count')
    x_values = [i+(bucket_cuttoffs[1]-bucket_cuttoffs[0]) for i in bucket_cuttoffs]
    for packet_class_str in CLASSES:
        packet_class_int = CLASSES[packet_class_str]
        counts = [d.get(packet_class_int, 0) for d in time_series_data]
        ax.plot(x_values, counts, label=packet_class_str)
    
    ax.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
    fig.tight_layout()

    ax.set_xticks(bucket_cuttoffs, [str(i) for i in bucket_cuttoffs], rotation=45, ha='right', rotation_mode='anchor', size=8)
    ax.xaxis.set_major_formatter(FormatStrFormatter('%0.2f'))

    fig.show()

    green_print('Chart is being displayed...')
    input('Press enter to clear charts and return to the main menu...')

    plt.close(fig)
    clear_screen()
    print()


def extract_conversation_features():
    """
    Extract features in the form of conversations from a cleaned file.
    Each conversation is a 2D array that is num_packets in conversation * num_features/nibbles
    All conversations must be padded/truncated to a certain length specified by CONVERSATION_LENGTH
    Protocols identified in CONVERSATION_CLASSES are identified. IP address is used if it is available, otherwise
    ethernet addresses are used (e.g. ARP conversations could not use IP address). If a packet could belong to two conversation
    classes, the more specific one is used (e.g. HTTP packet could be HTTP conversation or TCP conversation, if both are being captured)
    """
    target_file_path = get_existing_file('Enter the file you would like to analyze', None, CLEANED_FILEPATH)

    out_filename = get_new_file('Enter the relative path for the output (.npy) file', 'out.npy', OUTPUT_FILEPATH)
    y_out_filename = out_filename.split('.')[0] + '_y.npy'

    # Apparently it is more efficient to convert these to numpy arrays at the end
    X = []
    y = []
    conversation_dict = dict()
    next_index = 0

    # Counters
    conversations_saved = 0
    packets_saved = 0

    with open(target_file_path, 'r', encoding='utf-8') as target_file:
        for line in target_file:
            line_list = line.strip().split()
            packet_bytes = line_list[1]

            packet_layers = get_packet_layers(packet_bytes)

            layer_intersection = packet_layers & CONVERSATION_CLASSES
            if not layer_intersection:
                continue
            else:
                # If there are multiple, use whichever one has the higher enum value
                # e.g. HTTP will be selected over TCP
                protocol = max(layer_intersection, key=lambda x: x.value)

            # Find the correct src/dst address to use depending on what layers are present
            if PacketLayers.IPV4 in packet_layers:
                get_src_addr = get_src_ip
                get_dst_addr = get_dst_ip
            elif PacketLayers.IPV6 in packet_layers:
                get_src_addr = get_src_ipv6
                get_dst_addr = get_dst_ipv6
            elif PacketLayers.ETHERNET in packet_layers:
                get_src_addr = get_src_mac
                get_dst_addr = get_dst_mac
            else:
                yellow_print('Encountered a packet that does not have an layer from which to pull an address. Skipping...')
                continue

            # We must use ports to distinguish this conversation if it has a UDP or TCP layer
            if PacketLayers.TCP in packet_layers or PacketLayers.UDP in packet_layers:
                _get_src_port = get_src_port
                _get_dst_port = get_dst_port
            else:  # If it does not, fill those with dummy data
                _get_src_port = lambda x: '0000'
                _get_dst_port = lambda x: '0000'

            conversation = Conversation(get_src_addr(packet_bytes), get_dst_addr(packet_bytes), _get_src_port(packet_bytes), _get_dst_port(packet_bytes), protocol)
            if conversation not in conversation_dict:
                conversation_dict[conversation] = next_index
                X.append([])
                y.append(protocol.value)

                next_index += 1
                conversations_saved += 1
            
            conversation_index = conversation_dict[conversation]
            if len(X[conversation_index]) >= MAX_CONVERSATION_LENGTH:  # we already have CONVERSATION_LENGTH of these packets. Don't need more
                continue

            nibbles = [int(''.join(let), 16) for let in zip(*[iter(packet_bytes[:NUM_FEATURES*NIBBLES_PER_FEATURE])]*NIBBLES_PER_FEATURE)]
            # pad nibbles out to NUM_FEATURES
            if len(nibbles) < NUM_FEATURES:
                nibbles.extend([0]*(NUM_FEATURES-len(nibbles)))
            X[conversation_index].append(nibbles)
            packets_saved += 1

        # Remove conversations that are below MIN_CONVERSATION_LENGTH and pad conversations to MAX_CONVERSATION_LENGTH\
        # NOTE: Could do this more efficiently with numpy vectorization approach? Task for the future
        for i in range(len(X)-1, -1, -1):
            conversation_array = X[i]
            if len(conversation_array) < MIN_CONVERSATION_LENGTH:
                conversations_saved -= 1
                packets_saved -= len(conversation_array)
                del X[i]
                del y[i]
            elif len(conversation_array) < MAX_CONVERSATION_LENGTH:
                # Warning!! The way we extend this list, they are all the same one. A change in one will be seen on all of them
                # That is okay for now, but it could cause problems in the future
                conversation_array.extend([[0]*NUM_FEATURES]*(MAX_CONVERSATION_LENGTH-len(conversation_array)))

        np.save(out_filename, np.array(X, dtype=int))
        np.save(y_out_filename, np.array(y, dtype=int))

        green_print(f'Saved {conversations_saved} conversations and {packets_saved} packets.')
        protocols, counts = np.unique_counts(y)
        print_counts_dict(dict(zip([PacketLayers(protocol).name for protocol in protocols], counts)))
        
        print()
        input('Press enter to return to the main menu...')
        clear_screen()


def test_trained_model() -> None:
    """
    Load the weights from TRAINED_WEIGHTS_FILEPATH and the model using import
    Run a cleaned file through the model and calculate the accuracy
    """
    try:
        import torch
        from model import NetModel

        # Use default hyperparameters
        net_model = NetModel()
        net_model.load_state_dict(torch.load(TRAINED_WEIGHTS_FILEPATH))
        net_model.eval()  # put us in eval mode
    except ImportError:
        red_print('Something went wrong while importing the model from model.py')
        input('Press enter to return to the main menu...')
        clear_screen()
        return
    except:
        red_print('Something went wrong while loading the model weights.')
        input('Press enter to return to the main menu...')
        clear_screen()
        return
    
    green_print('\nSuccessfully loaded the model and weights!\n')

    # Get the cleaned file and make the test structures
    target_filepath = get_existing_file('Enter a cleaned file with which to test the model', None, CLEANED_FILEPATH)

    X = []
    y = []

    # Loop to extract the features from this file
    with open(target_filepath, 'r', encoding='utf-8') as target_file:
        for line in target_file:
            line_list = line.split()
            if len(line_list) != 2:
                yellow_print('WARNING: A line in this file appears to be malformed.')
                continue
            packet_bytes = line_list[1]
            packet_class = get_packet_class(packet_bytes, CLASSES)
            # This could be an 'Other' packet that we should ignore if this returns -1
            if packet_class == -1:
                continue

            nibbles = [int(''.join(c for c in let), 16) for let in zip(*[iter(packet_bytes[:NUM_FEATURES*NIBBLES_PER_FEATURE])]*NIBBLES_PER_FEATURE)]
            # pad to NUM_FEATURES length
            if len(nibbles) < NUM_FEATURES:
                nibbles.extend([0] * (NUM_FEATURES-len(nibbles)))
            
            X.append(nibbles)
            y.append(packet_class)
    
    X_tensor = torch.tensor(X, dtype=torch.float32)
    y_tensor = torch.tensor(y, dtype=torch.int16)

    clear_screen()
    print(f'Extracted {X_tensor.shape[0]} packets')
    
    # Do the testing!
    correct_counter = 0
    num_classes = net_model.output.out_features
    with torch.no_grad():
        outputs = net_model(X_tensor)
        _, predicted = torch.max(outputs, 1)
        correct_counter = (predicted == y_tensor).sum().item()

        # Get true/predicted bin counts
        true_class_bins = torch.bincount(y_tensor, minlength=num_classes)
        predicted_class_bins = torch.bincount(predicted, minlength=num_classes)

        # Make confusion matrix
        indices = y_tensor * num_classes + predicted
        cm_flat = torch.bincount(indices, minlength=num_classes**2)
        cm = cm_flat.reshape(num_classes, num_classes)    


    green_print('\nTesting complete!')
    print(f'Accuracy: {100*(correct_counter/len(y)):.2f}%')

    # Print true counts and predicted counts
    print('\nTrue/Predicted Class Counts:')
    reverse_classes = dict(zip(CLASSES.values(), CLASSES.keys()))
    for class_index, pair in enumerate(zip(true_class_bins, predicted_class_bins)):
        true_count, predicted_count = pair
        print(f'{reverse_classes[class_index]: <20} True: {true_count: <8} Predicted: {predicted_count: <8}')
    
    print()

    # Print confusion matrix (rows are true index, columns are predicted)
    print(' '*20, end='')
    print(''.join(f'{reverse_classes[i]: <20}' for i in range(cm.shape[0])))
    for i, row in enumerate(cm):
        for j, val in enumerate(row):
            color = GREEN_COLOR if i == j else RED_COLOR
            if j == 0:  # print the row header
                print(f'{reverse_classes[i]: <20}', end='')
            print(f'{color}{val: <20}{DEFAULT_COLOR}', end='')
        print()

    input('\nPress enter to return to the main menu...')
    clear_screen()


def print_counts_dict(counts_dict: dict | None, max_lines: int = MAX_BAR_CHART_BARS) -> None:
    """
    Convenience function for printing out a dictionary containing packet counts
    
    Args:
        counts_dict (dict): dictionary containing the labels and counts
        max_lines (int): the maximum number of lines to print
    """
    if counts_dict is None or len(counts_dict) == 0:
        print('No data collected for this statistic')
        return
    extra_values = 0
    for i, (mac, count) in enumerate(counts_dict.items()):
        if i < max_lines:
            print(f'{mac:.<40}{count}')
        else:
            extra_values += 1
    if extra_values:
        print(f'{extra_values} more values not shown')


def print_text_analysis(capture_data: CaptureData) -> None:
    """Display text-formatted information based on the capture data"""
    print('Overall Counts:')
    print(f'{"Average Length":.<40}{capture_data.average_length:.2f}')
    print(f'{"Total number of packets":.<40}{capture_data.num_packets}')
    print(f'{"Total Ethernet II packets":.<40}{capture_data.eth_num}')
    print(f'{"Total IP packets":.<40}{capture_data.ip_num}')
    print(f'{"Total TCP packets":.<40}{capture_data.tcp_num}')
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
def get_packet_layers(packet_bytes: str) -> set[Enum]:
    """Find all the encapsulated layers in this packet"""
    layers = set()
    # for right now, just assume everything is ethernet
    layers.add(PacketLayers.ETHERNET)

    if ETH_TYPES.get(get_eth_type(packet_bytes)) == 'ARP':
        layers.add(PacketLayers.ARP)
    elif ETH_TYPES.get(get_eth_type(packet_bytes)) == 'IPv4':
        layers.add(PacketLayers.IPV4)
        if IP_PROTOS.get(get_ip_proto(packet_bytes)) == 'ICMP':
            layers.add(PacketLayers.ICMP)
        if IP_PROTOS.get(get_ip_proto(packet_bytes)) == 'TCP':
            layers.add(PacketLayers.TCP)
            if TCP_SERVICE_PORTS.get(get_src_port(packet_bytes)) == 'HTTP' or TCP_SERVICE_PORTS.get(get_dst_port(packet_bytes)) == 'HTTP':
                layers.add(PacketLayers.HTTP)
        elif IP_PROTOS.get(get_ip_proto(packet_bytes)) == 'UDP':
            layers.add(PacketLayers.UDP)
            if UDP_SERVICE_PORTS.get(get_src_port(packet_bytes)) == 'DNS' or UDP_SERVICE_PORTS.get(get_dst_port(packet_bytes)) == 'DNS':
                layers.add(PacketLayers.DNS)
    else:
        layers.add(PacketLayers.IPV6)

    return layers


def get_ip_class(class_name: str, classes: dict[str, int], packet_bytes: str) -> int:
    """
    Tests to see if this class is present in classes with src/dst ip qualifiers
    If it is return it as that class. If it is not but the class exists in classes without a src/dst qualifier, then return that class
    If the class is not present at all in classes, then return -1

    Args:
        class_name (str): the class name we are testing
        classes (dict): classes dictionary
        packet_bytes (str): bytes of this packet
    Return:
        (int): the int class of this packet, -1 if this class is not present at all
    """
    src_ip = get_printable_ip(get_src_ip(packet_bytes))
    dst_ip = get_printable_ip(get_dst_ip(packet_bytes))

    possible_class_name = f'{class_name}-src-{src_ip}'
    if possible_class_name in classes.keys():
        return classes[possible_class_name]
    possible_class_name = f'{class_name}-dst-{dst_ip}'
    if possible_class_name in classes.keys():
        return classes[possible_class_name]
    if class_name in classes.keys():
        return classes[class_name]
    else:
        return -1


# returns packet class - See CLASSES definition at the top of the file
def get_packet_class(packet_bytes: str, classes: dict[str, int] = CLASSES) -> int:
    """Get the class of this packet of the ones we are interested in
    
    Args:
        packet_bytes (str): raw packet bytes to analyze
    Returns:
        int: integer representing the packet class. -1 if it is not a class we care about
    """
    other = classes.get('Other')
    if not other:
        raise ValueError('No "other" value in classes!')

    if ETH_TYPES.get(get_eth_type(packet_bytes)) == 'ARP':  # ARP - is it reply or request
        return classes.get(ARP_OPCODES.get(get_arp_opcode(packet_bytes), 'Other'), other)

    elif ETH_TYPES.get(get_eth_type(packet_bytes)) == 'IPv4':  # IPv4
        if IP_PROTOS.get(get_ip_proto(packet_bytes)) == 'ICMP':  # ICMP - echo reply or request
            if ICMP_TYPES.get(get_icmp_type(packet_bytes), 'Other') == 'ICMP Echo Request':
                if (ip_class := get_ip_class('ICMP Echo Request', classes, packet_bytes)) != -1:
                    return ip_class
            elif ICMP_TYPES.get(get_icmp_type(packet_bytes), 'Other') == 'ICMP Echo Reply':
                if (ip_class := get_ip_class('ICMP Echo Reply', classes, packet_bytes)) != -1:
                    return ip_class
            elif (ip_class := get_ip_class('ICMP', classes, packet_bytes)) != -1:
                return ip_class
            return other
        elif IP_PROTOS.get(get_ip_proto(packet_bytes)) == 'TCP':  # TCP
            src_port_service = TCP_SERVICE_PORTS.get(get_src_port(packet_bytes), 'Other')
            dst_port_service = TCP_SERVICE_PORTS.get(get_dst_port(packet_bytes), 'Other')
            interesting_port_service = src_port_service if src_port_service != 'Other' else dst_port_service
            if (ip_class := get_ip_class(interesting_port_service, classes, packet_bytes)) != -1:
                return ip_class
            return other
        elif IP_PROTOS.get(get_ip_proto(packet_bytes)) == 'UDP':  # UDP
            # need extra logic for DNS or DNS-query and DNS-response
            src_port_service = UDP_SERVICE_PORTS.get(get_src_port(packet_bytes), 'Other')
            dst_port_service = UDP_SERVICE_PORTS.get(get_dst_port(packet_bytes), 'Other')
            # If they both are 'Other' just stop now
            if src_port_service == 'Other' and dst_port_service == 'Other':
                return other
            # Need to have some extra logic here because query/response depends on which src/dst port is the DNS port number
            if src_port_service == 'DNS' or dst_port_service == 'DNS':
                if (ip_class := get_ip_class('DNS', classes, packet_bytes)) != -1:
                    return ip_class
                if src_port_service == 'DNS':
                    if (ip_class := get_ip_class('DNS-response', classes, packet_bytes)) != -1:
                        return ip_class
                else:
                    if (ip_class := get_ip_class('DNS-query', classes, packet_bytes)) != -1:
                        return ip_class
            else:  # not DNS
                interesting_port_service = src_port_service if src_port_service != 'Other' else dst_port_service
                if (ip_class := get_ip_class(interesting_port_service, classes, packet_bytes)) != -1:
                    return ip_class
            return other
        else:  # neither TCP nor UDP
            return other

    elif ETH_TYPES.get(get_eth_type(packet_bytes)) == 'IPv6':
        if IPV6_NEXT_HEADERS.get(get_ipv6_proto(packet_bytes)) == 'UDP':
            # offset=20 because the ipv6 header is 20 bytes larger than the ipv4 header
            return classes.get(UDP_SERVICE_PORTS.get(get_src_port(packet_bytes, offset=20), 'Other'), other)
        elif IPV6_NEXT_HEADERS.get(get_ipv6_proto(packet_bytes)) == 'ICMPv6':
            return classes.get('ICMPv6', other)
        elif IPV6_NEXT_HEADERS.get(get_ipv6_proto(packet_bytes)) == 'hop-by-hop':
            return classes.get(IPV6_HOP_BY_HOP_NEXT_HEADERS.get(get_ipv6_hop_by_hop_next_header(packet_bytes), 'Other'), other)
        else:  # not udp
            return other
    elif int(get_eth_type(packet_bytes), 16) < ETH_802_3_THRESHOLD:  # not an Ethernet II frame
        return classes.get(LLC_DSAP.get(get_llc_dsap(packet_bytes), 'Other'), other)
    else:
        return other


def extract_features(X_2D = False):
    """Extract the features we want from the data in 1D or 2D format"""
    if not X_2D:
        num_features = NUM_FEATURES
    else:
        num_features = CNN_FEATURES_DIMENSION*CNN_FEATURES_DIMENSION

    target_file_path = get_existing_file('Enter the name or number of the file to analyze. Use "help" for help', None, CLEANED_FILEPATH)

    # loop to let the user split all the classes they want
    classes = CLASSES.copy()
    while True:
        help_msg = 'Enter a valid class from the list below:\n'
        help_msg += '\n'.join(class_name for class_name in classes.keys()) + '\n'
        class_split_selection = get_user_input('Enter a class to split, if desired, or nothing to continue. (Use "help" for help)', '', str, help_msg, lambda x: x in classes.keys())
        if class_split_selection:
            classes = split_class(class_split_selection, target_file_path, classes)
        else:
            break
    
    # now let the user redact an fields that they would like before extracting the features
    redact_func_list = get_redact_functions()

    out_filename = get_new_file('Enter the relative path for the output (.npy) file', 'out.npy', OUTPUT_FILEPATH)
    y_out_filename = out_filename.split('.')[0] + '_y.npy'
    q_out_filename = out_filename.split('.')[0] + '_q.npy'

    # Initialize X, y
    # y holds our classes e.g. [ARP Request, ARP Reply, ICMP Echo Request, ICMP Echo Reply, TLS, HTTP, DNS, QUIC, Other]
    y = []
    X = []

    # Initialize counters
    packets_analyzed = 0
    samples_per_class = {packet_class: 0 for packet_class in classes.values() if packet_class != -1}
    features_extracted = 0
    with open(target_file_path, 'r', encoding='utf-8') as target_file:
        # Create a list of nibbles for each packet in target_file
        for line in target_file:
            line_list = line.split()
            if len(line_list) != 2:
                yellow_print('WARNING: A line in the target file appears to be malformed')
                continue
            packet_bytes = line_list[1]
            packet_class = get_packet_class(packet_bytes, classes=classes)

            # We don't care about this packet
            if packet_class == -1:
                continue
            if not samples_per_class[packet_class] < SAMPLES_PER_CLASS:
                continue

            # Increment count and add to y
            samples_per_class[packet_class] += 1
            y.append(packet_class)

            # redact bytes if necessary before grabbing the nibbles
            for func in redact_func_list:
                packet_bytes = func(packet_bytes)

            # Create X and convert each hex to int value
            nibbles = [int(''.join(c for c in let), 16) for let in zip(*[iter(packet_bytes[:num_features*NIBBLES_PER_FEATURE])]*NIBBLES_PER_FEATURE)]
            # pad to NUM_FEATURES length
            if len(nibbles) < num_features:
                nibbles.extend([0] * (num_features-len(nibbles)))

            # increment counts
            features_extracted += len(nibbles)
            packets_analyzed += 1

            # append to our X data structure
            # if we are outputting in 2D, then convert it to that format before appending
            if not X_2D:
                X.append(nibbles)
            else:
                nibbles_2d = [nibbles[i*CNN_FEATURES_DIMENSION:(i+1)*CNN_FEATURES_DIMENSION] for i in range(CNN_FEATURES_DIMENSION)]
                X.append(nibbles_2d)

    # convert x and y to ndarrays
    y_arr = np.array(y, dtype=int)
    X_arr = np.array(X, dtype=int)
    q_arr = np.array([list(classes.keys()), list(classes.values())])

    # save both X and y to files and q (our classes)
    np.save(y_out_filename, y_arr)
    np.save(out_filename, X_arr)
    np.save(q_out_filename, q_arr)

    print('Packet class counts:')
    not_enough_packets_warning = False
    for packet_class, count in samples_per_class.items():
        if count == 0:
            continue
        print(f'{dict(zip(classes.values(), classes.keys())).get(packet_class):.<40}{count}')
        if count < SAMPLES_PER_CLASS:
            not_enough_packets_warning = True
    print()
    if not_enough_packets_warning:
        yellow_print(f'WARNING: One or more classes do not have enough packets ({SAMPLES_PER_CLASS})!\n')

    green_print(f'Data from {target_file_path} successfully saved to {out_filename}')
    green_print(f'Targets have been saved to {y_out_filename}')
    green_print(f'Analyzed {features_extracted} features from {packets_analyzed} packets!')
    input('\nPress enter to return to the main menu...')
    clear_screen()


def split_class(class_selection: str, target_file_path: str, classes: dict[str, int]):
    """
    Helps the user split the provided class based on the data from this file

    Args:
        class_selection (str): the class we are trying to split
        target_file_path (str): file we are currently working with
        classes (dict): the classes dictionary to modify
    Returns:
        (dict): the modified parameter classes after the class has been split
    """
    # TODO: Modify to work with more than IP address 
    # examine all those packets
    class_selection_code = classes.get(class_selection)
    src_ip_counts = {}
    dst_ip_counts = {}
    with open(target_file_path, 'r') as f:
        for line in f:
            packet_bytes = line.split()[1]
            packet_class = get_packet_class(packet_bytes, classes=classes)
            if packet_class == class_selection_code and PacketLayers.IPV4 in get_packet_layers(packet_bytes):
                src_ip = get_printable_ip(get_src_ip(packet_bytes))
                dst_ip = get_printable_ip(get_dst_ip(packet_bytes))
                src_ip_counts[src_ip] = src_ip_counts.get(src_ip, 0) + 1
                dst_ip_counts[dst_ip] = dst_ip_counts.get(dst_ip, 0) + 1
    
    # Reduce dictionaries down to only IPs that have enough samples
    src_ip_counts = {ip: count for ip, count in src_ip_counts.items() if count >= SAMPLES_PER_CLASS}
    dst_ip_counts = {ip: count for ip, count in dst_ip_counts.items() if count >= SAMPLES_PER_CLASS}

    help = 'Source IP Counts:\n'
    counter = 0
    for ip, count in src_ip_counts.items():
        help += f'{counter}: {ip:.<40}{count}\n'
        counter += 1
    help += '\nDestination IP Counts:\n'
    for ip, count in dst_ip_counts.items():
        help += f'{counter}: {ip:.<40}{count}\n'
        counter += 1
    help += '\n'
    print(help)

    while True:
        ip_selections = get_user_input('Enter the numbers seperated by commas for the IP addresses to split this class on.', '', str, help, lambda x: not x or (len(x.split(',')) > 1 and all(int(i) < counter for i in x.split(','))))
        if not ip_selections:  # the user entered nothing, so we should cancel this
            clear_screen()
            red_print('Canceling splitting on this class...\n')
            return classes
        ip_selections = ip_selections.split(',')
        # Make sure all of them are from either src or dst ips
        ip_selections = [int(i) for i in ip_selections]
        if not (all(int(num) < len(src_ip_counts) for num in ip_selections) or all(int(num) >= len(src_ip_counts) for num in ip_selections)):
            clear_screen()
            red_print('All selections must be either source or destination IP addresses\n')
        else:
            break

    del classes[class_selection]

    if ip_selections[0] < len(src_ip_counts):
        for selection in ip_selections:
            classes[f'{class_selection}-src-{list(src_ip_counts.keys())[selection]}'] = -1  # placeholder value
    else:
        ip_selections = [i-len(src_ip_counts) for i in ip_selections]
        for selection in ip_selections:
            classes[f'{class_selection}-dst-{list(dst_ip_counts.keys())[selection]}'] = -1  # placeholder value
    
    # go through and fix all the class number values now (not really necessary but I want to)
    counter = 0
    for key in classes:
        if key == 'Other' and CLASSES['Other'] == -1:
            continue
        classes[key] = counter
        counter += 1
    if CLASSES['Other'] == -1:
        classes['Other'] = -1

    return classes

  
def main():
    """Main function"""
    # get the operating system
    if OS_NAME in {'Windows', 'Linux'}:
        green_print(f'Detected running on {OS_NAME} system!')
    else:
        red_print(f'Detected running on {OS_NAME} system which is not supported.')
        sys.exit()

    # check that captures and cleaned file paths exist
    if not os.path.exists(CAPTURES_FILEPATH):
        red_print(f'The path for capture files "{CAPTURES_FILEPATH}" does not exist. Qutting...')
        sys.exit()
    if not os.path.exists(CLEANED_FILEPATH):
        red_print(f'The path for cleaned files "{CLEANED_FILEPATH}" does not exist. Quitting...')
        sys.exit()
    if not os.path.exists(OUTPUT_FILEPATH):
        yellow_print(f'The path for output files does not exist...creating "{OUTPUT_FILEPATH}" now...\n')
        os.makedirs(OUTPUT_FILEPATH)

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
            sys.exit()

        if user_input == 1:
            capture_traffic()
        elif user_input == 2:
            clean_captures()
        elif user_input == 3:
            analyze_data()
        elif user_input == 4:
            time_series_analysis()
        elif user_input == 5:
            extract_features()
        elif user_input == 6:
            extract_features(X_2D=True)
        elif user_input == 7:
            extract_conversation_features()
        elif user_input == 8:
            combine_cleaned_captures()
        elif user_input == 9:
            test_trained_model()
        else:
            clear_screen()
            red_print('Enter the number for a valid option\n')


if __name__ == '__main__':
    main()
