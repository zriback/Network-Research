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

# "Linux" or "Windows"
# found when running the main function
os_name = ''

@dataclass
class CaptureData:
    num_packets: int = 0
    average_length: float = 0
    src_mac_counts: dict = None
    dst_mac_counts: dict = None
    src_ip_counts: dict = None
    dst_ip_counts: dict = None
    eth_type_counts: dict = None
    ip_proto_counts: dict = None
    src_port_counts: dict = None
    dst_port_counts: dict = None
    microsec_times: list = None


CAPTURES_FILEPATH = 'C:\\Users\\zacha\\vscode\\Network-Research\\captures'
CLEANED_FILEPATH = 'C:\\Users\\zacha\\vscode\\Network-Research\\cleaned'

PACKET_DELIMETER = b'PACKET_SEPARATOR_01010101'

# the time value will always be padded with zeros to look like
# TIME_01010101_(0000000000)
EMBEDDED_TIME_VALUE_LENGTH = 10
EMBEDDED_TIME_FORMAT = 'TIME_01010101_({})'
TOTAL_EMBEDDED_TIME_LENGTH = len(EMBEDDED_TIME_FORMAT)-2+EMBEDDED_TIME_VALUE_LENGTH
EMBEDDED_TIME_FORMAT_REGEX = br'TIME_01010101_\((\d{10})\)'

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
SRC_PORT_LOC = 34
DST_PORT_LOC = 36

ETH_TYPES = {
    b'\x08\x00' : 'IPv4',
    b'\x08\x06' : 'ARP',
    b'\x86\xDD' : 'IPv6'
}

IP_PROTOS = {
    b'\x01' : 'ICMP',
    b'\x06' : 'TCP',
    b'\x11' : 'UDP',
}


def get_printable_ip(ip_bytes: bytes) -> str:
    if len(ip_bytes) != 4:
        return None
    ip_string = '.'.join(str(int(byte)) for byte in ip_bytes)
    return ip_string


def get_printable_mac(mac_bytes: bytes) -> str:
    if len(mac_bytes) != 6:
        return None
    mac_string = ':'.join(f'{byte:02X}' for byte in mac_bytes)
    return mac_string


def get_header_field(data: bytes, loc: int, length: int) -> bytes:
    return data[loc:loc+length]

# Partial functions for getting each header field
get_src_mac = partial(get_header_field, loc=SRC_MAC_LOC, length=6)
get_dst_mac = partial(get_header_field, loc=DST_MAC_LOC, length=6)
get_src_ip = partial(get_header_field, loc=SRC_IP_LOC, length=4)
get_dst_ip = partial(get_header_field, loc=DST_IP_LOC, length=4)
get_eth_type = partial(get_header_field, loc=ETH_TYPE_LOC, length=2)
get_ip_proto = partial(get_header_field, loc=IP_PROTO_LOC, length=1)
get_src_port = partial(get_header_field, loc=SRC_PORT_LOC, length=2)
get_dst_port = partial(get_header_field, loc=DST_PORT_LOC, length=2)


# returns each 'line' from the file where a 'line' is separated by the sep value
def read_cleaned_file(filename, sep):
    file = open(filename, 'rb')
    file_contents = b''
    bytes_read = 0
    lines_read = 0
    while True:
        this_read = file.read(128)

        if not this_read:  # it is the end of the file. Yield what we currently have then quit
            yield file_contents
            break

        file_contents += this_read
        sep_loc = file_contents.find(sep)

        if sep_loc == -1:  # have not found the end of this 'line' yet
            continue

        line = file_contents[:sep_loc]
        file.seek(sep_loc + (len(sep)*(lines_read+1) + bytes_read))  # so the next time we start reading from the beginning of the next line
        file_contents = b''
        bytes_read += len(line)
        lines_read += 1
        yield line

    file.close()


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
    output += '\t(3) Analyze Data'
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
                print(RED_COLOR + 'No default value to use. Enter a valid value.\n' + DEFAULT_COLOR)
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
                print(RED_COLOR + 'Enter a valid value\n' + DEFAULT_COLOR)
                continue
        break
    print()
    return user_input


def capture_traffic():
    '''Runs tshark command to capture traffic. Stored in the CAPTURES_FILEPATH directory
    Output file named with current timestamp and saved as k12 text file'''
    adapter_names = '' 
    for nice_name in [f'{name.ips[0].nice_name}' for name in ifaddr.get_adapters()]:
        adapter_names += (nice_name + '\n')
    capture_interface_help = f'Enter the name of a valid interface:\n{adapter_names}'
    
    while (capture_interface := get_user_input('Enter the capture interface. Use "help" for help', None, str, capture_interface_help)) not in adapter_names:
        clear_screen()
        print(RED_COLOR + 'Not a valid adapter name\n' + DEFAULT_COLOR)

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
        '-f', capture_filter,
        '-w', f'{full_path}.pcap',
        '-q'
    ]

    if not manual_stop:
        tshark_command_list.extend(['-a', stop_method])
    
    try:
        tshark_process = sp.Popen(tshark_command_list, stdout=sp.PIPE, stderr=sp.PIPE)
    except FileNotFoundError:
        print(RED_COLOR + 'tshark could not be found. Perhaps it needs to be installed?' + DEFAULT_COLOR)
        print(RED_COLOR + 'Kicking you back to the main menu...\n' + DEFAULT_COLOR)
        return
    
    clear_screen()
    print(GREEN_COLOR + 'Started capture!' + DEFAULT_COLOR)
    print(f'Using command: {" ".join(tshark_command_list)}', end='\n\n')

    time.sleep(.5)
    if tshark_process.poll() is not None:  # something went wrong
        err = tshark_process.communicate()[1]
        print(RED_COLOR + 'Something might have gone wrong with that tshark command.' + DEFAULT_COLOR)
        print(err.decode())
        print('Returning to main menu...\n')
        return

    if manual_stop:
        input('Press Enter to stop the capture...')
        print(YELLOW_COLOR + 'Stopping tshark process...' + DEFAULT_COLOR)
        tshark_process.terminate()
    tshark_process.wait()
    
    print(GREEN_COLOR + 'Capture successfully terminated.' + DEFAULT_COLOR)
    
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
    print(YELLOW_COLOR + 'Cleaning captures...' + DEFAULT_COLOR)

    for capture in target_captures_list:
        if not capture.endswith('.txt'):
            capture = capture + '.txt'
        print('\t' + YELLOW_COLOR + f'Cleaning {capture}' + DEFAULT_COLOR)
        capture_filepath = os.path.join(CAPTURES_FILEPATH, capture)
        output_filepath = os.path.join(CLEANED_FILEPATH, capture)
        
        try:
            capture_file = open(capture_filepath, 'r')
        except FileNotFoundError:
            print('\t' + RED_COLOR + f'The file {capture} could not be found. Skipping...')
            continue
        output_file = open(output_filepath, 'wb')

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
            if byte_string is not None:  # write the delimeter if this is NOT the first time
                output_file.write(PACKET_DELIMETER)
            else:  # this is the first time, so set starting time info
                start_times = re.split(r':|,', timestamp)
                start_times = [int(num) for num in start_times]
            
            byte_string = b''
            packet_bytes_list = line[6:-2].split('|')
            for hex_string in packet_bytes_list:
                byte = int(hex_string, 16).to_bytes(1, 'big')
                byte_string += byte

            this_times = re.split(r':|,', timestamp)
            this_times = [int(num) for num in this_times]
            diff_times = [this_times[i] - start_times[i] for i in range(len(start_times))]

            # get the difference in only microseconds
            microsec_diff = diff_times[0]*3600000000 + diff_times[1]*60000000 + diff_times[2]*1000000 + diff_times[3]*1000 + diff_times[4]
            microsec_diff_string = str(microsec_diff)
            while len(microsec_diff_string) < EMBEDDED_TIME_VALUE_LENGTH:
                microsec_diff_string = '0' + microsec_diff_string
            time_diff_output = EMBEDDED_TIME_FORMAT.format(microsec_diff_string)

            # write to cleaned output file
            output_file.write(time_diff_output.encode())
            output_file.write(byte_string)
        
        capture_file.close()
        output_file.close()
        
    print(GREEN_COLOR + 'Cleaning finished!' + DEFAULT_COLOR)
    print(f'Check {CLEANED_FILEPATH} for the cleaned file(s).')
    input('Press enter to return to the main menu...')
    clear_screen()


def get_capture_data(packets):
    total_length = 0
    num_packets = 0

    eth_type_counts = {}
    ip_proto_counts = {}
    src_mac_counts = {}
    src_ip_counts = {}
    src_port_counts = {}
    dst_port_counts = {}
    microsec_times = []

    for line in packets:
        if not line:
            print(RED_COLOR + 'Something is wrong with this data. It is possible no data was captured')
            return None

        packet_bytes = line[TOTAL_EMBEDDED_TIME_LENGTH:]

        # looks though ONLY the first 25 charactes of the line for the full time identifier
        # subtract 2 because of the {} in the format string
        microsec_time = int(re.match(EMBEDDED_TIME_FORMAT_REGEX, line[:TOTAL_EMBEDDED_TIME_LENGTH]).group(1).decode())
        microsec_times.append(microsec_time)

        # grab appropriate data from the packet
        packet_length = len(packet_bytes)
        eth_type = get_eth_type(packet_bytes)
        src_mac = get_src_mac(packet_bytes)
        dst_mac = get_dst_mac(packet_bytes)

        mac_string = get_printable_mac(src_mac)
        src_mac_counts[mac_string] = src_mac_counts.setdefault(mac_string, 0) + 1

        eth_type_string = ETH_TYPES.get(eth_type, 'Other')
        # add one to the count for this eth_type, if it does not exist create it
        eth_type_counts[eth_type_string] = eth_type_counts.setdefault(eth_type_string, 0) + 1

        if eth_type_string == 'IPv4':
            ip_proto = get_ip_proto(packet_bytes)
            src_ip = get_src_ip(packet_bytes)
            dst_ip = get_dst_ip(packet_bytes)

            ip_string = get_printable_ip(src_ip)
            src_ip_counts[ip_string] = src_ip_counts.setdefault(ip_string, 0) + 1

            ip_proto_string = IP_PROTOS.get(ip_proto, 'Other')
            ip_proto_counts[ip_proto_string] = ip_proto_counts.setdefault(ip_proto_string, 0) + 1
        
        # TCP packet
        if eth_type_string == 'IPv4' and ip_proto_string == 'TCP':
            src_port = str(int.from_bytes(get_src_port(packet_bytes), byteorder='big'))
            dst_port = str(int.from_bytes(get_dst_port(packet_bytes), byteorder='big'))

            src_port_counts[src_port] = src_port_counts.setdefault(src_port, 0) + 1
            dst_port_counts[dst_port] = dst_port_counts.setdefault(dst_port, 0) + 1

        total_length += packet_length
        num_packets += 1
    
    average_length = total_length / num_packets

    # place all data into the class structure
    # 'sort' the dictionaries contents by key (implementation specific)
    capture_data = CaptureData(
        num_packets=num_packets,
        average_length=average_length,
        src_mac_counts=dict(sorted(src_mac_counts.items(), key=lambda item: item[1], reverse=True)),
        dst_mac_counts=None,
        src_ip_counts=dict(sorted(src_ip_counts.items(), key=lambda item: item[1], reverse=True)),
        dst_ip_counts=None,
        eth_type_counts=dict(sorted(eth_type_counts.items(), key=lambda item: item[1], reverse=True)),
        ip_proto_counts=dict(sorted(ip_proto_counts.items(), key=lambda item: item[1], reverse=True)),
        src_port_counts=dict(sorted(src_port_counts.items(), key=lambda item: item[1], reverse=True)),
        dst_port_counts=dict(sorted(dst_port_counts.items(), key=lambda item: item[1], reverse=True)),
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
                print(RED_COLOR + 'That number is out of range.' + DEFAULT_COLOR + '\n')
                continue
            target_file = files[user_num_selection]
            # found a valid file
            break     
        except ValueError:  # not a number. User is entering a file name
            if not user_selection.endswith('.txt'):
                user_selection = user_selection + '.txt'
            if user_selection not in files:
                print(RED_COLOR + f'Could not find the file {user_selection}' + DEFAULT_COLOR + '\n')
                continue
            # found a valid file
            target_file = user_selection
            break

    clear_screen()

    target_file_path = os.path.join(CLEANED_FILEPATH, target_file)
    cleaned_file_packets = read_cleaned_file(target_file_path, PACKET_DELIMETER)
    capture_data = get_capture_data(cleaned_file_packets)

    if capture_data is None:
        print(RED_COLOR + 'No data to analyze' + DEFAULT_COLOR)
        input('Press enter to clear charts and return to the main menu...')
        clear_screen()
        print()
        return

    print(GREEN_COLOR + 'Analysis complete!' + DEFAULT_COLOR)
    print()

    print(f'Average Length: {capture_data.average_length:.2f}')
    print(f'Total number of packets: {capture_data.num_packets}')

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
    labels = list(capture_data.src_port_counts.keys())[:MAX_BAR_CHART_BARS]
    counts = list(capture_data.src_port_counts.values())[:MAX_BAR_CHART_BARS]
    this_ax.bar(labels, counts)
    this_ax.set_title('Source Port Counts')
    this_ax.set_xlabel('Source Port')
    this_ax.set_ylabel('Counts')
    this_ax.set_xticks(this_ax.get_xticks(), this_ax.get_xticklabels(), rotation=45, ha='right', rotation_mode='anchor', size=8)

    # 1,2 (packet times histogram)
    this_ax = ax[1,2]
    data = [val/1000000 for val in capture_data.microsec_times]
    counts, bins, patches = this_ax.hist(data, bins=10)
    this_ax.set_title('Packet Time Histogram')
    this_ax.set_xlabel('Packet Time (s)')
    this_ax.set_ylabel('Frequency')
    this_ax.set_xticks(bins, bins, rotation=45, ha='right', rotation_mode='anchor', size=8)
    this_ax.xaxis.set_major_formatter(FormatStrFormatter('%0.2f'))

    # # display the figure
    # fig.show()

    # large histogram
    large_histogram_fig = plt.figure()
    large_histogram_fig.set_figheight(6)
    large_histogram_fig.set_figwidth(12)
    this_ax = large_histogram_fig.add_subplot(1, 1, 1)
    data = [val/1000000 for val in capture_data.microsec_times]
    counts, bins, patches = this_ax.hist(data, bins=50)
    this_ax.set_title('Packet Time Histogram')
    this_ax.set_xlabel('Packet Time (s)')
    this_ax.set_ylabel('Frequency')
    this_ax.set_xticks(bins, bins, rotation=45, ha='right', rotation_mode='anchor', size=8)
    this_ax.xaxis.set_major_formatter(FormatStrFormatter('%0.2f'))
    
    fig.show()
    large_histogram_fig.show()

    print(GREEN_COLOR + 'Charts are being displayed...' + DEFAULT_COLOR)
    input('Press enter to clear charts and return to the main menu...')
    
    # close figures
    plt.close(fig)
    plt.close(large_histogram_fig)
    
    clear_screen()
    print()


def main():
    # get the operating system
    global os_name
    os_name = platform.system()
    if os_name == 'Windows' or os_name == 'Linux':
        print(GREEN_COLOR + f'Detected running on {os_name} system!' + DEFAULT_COLOR)
    else:
        print(RED_COLOR + f'Detected running on {os_name} system which is not supported.' + DEFAULT_COLOR)
        exit()

    while True:
        print_menu()
        try:
            user_input = int(input('Select an option: ').strip())
        except ValueError:
            clear_screen()
            print(RED_COLOR + 'Please enter a valid number\n' + DEFAULT_COLOR)
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
        else:
            clear_screen()
            print(RED_COLOR + 'Enter the number for a valid option\n' + DEFAULT_COLOR)


if __name__ == '__main__':
   main()
    
