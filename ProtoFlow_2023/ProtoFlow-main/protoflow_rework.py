#!/usr/bin/env python3

### LAST OPENED & EDITED: Saturday January 14, 2023

# Tool: Version B - may be consolidated later when time permits. (Allows for multiple entries from flows thresholds)

import os
import sys
import pyshark as ps
import numpy as np
import pandas as pd
import itertools as it
import traceback
from scipy import stats as st


FLOW_SEQUENCE_THRESHOLD = 1000 #900 # threshold for distinct entire (one minute = 60,000 ms)

outfile_name = "packet_flow_out.csv"
protocol_used = ''

flow_list = list()

csv_header_names = list()
zb_two_byte_dict = dict()


class FlowTableEntry:


    def __init__(self, src_oui, src_mac, initial_packet_size, dst_oui, dst_mac, init_time_captured_epoch_sec):
        
        self.src_oui = src_oui
        self.src_mac = src_mac
        self.dst_oui = dst_oui
        self.dst_mac = dst_mac

        self.time_captured_epoch_ms = float(init_time_captured_epoch_sec) * 1_000
        self.packet_list = list()
        self.packet_list.append(initial_packet_size)

        self.latest_time = float(init_time_captured_epoch_sec)
        self.latest_time_ms = self.latest_time * 1_000

        self.minimum_packet_size = 0.0
        self.maximum_packet_size = 0.0
        self.standard_deviation = 0.0
        self.most_occuring_size = 0.0
        self.mean_packet_size = 0.0
        self.avg_packet_size = 0.0
        self.bytes_per_ms = 0.0
        self.variance_in_distribution = 0.0
        #self.total_packets_in_session = 0.0
        #self.total_duration_in_session = 0.0


    def update_time_with_cap_time(self, cap_time_sec):

        self.latest_time_ms = (cap_time_sec * 1_000)

    def calculate_final_metrics(self):
        self.minimum_packet_size = np.min(self.packet_list)
        self.maximum_packet_size = np.max(self.packet_list)
        self.standard_deviation = np.std(self.packet_list)
        self.most_occuring_size = int(st.mode(self.packet_list)[0])
        self.mean_packet_size = np.mean(self.packet_list)
        self.avg_packet_size = np.average(self.packet_list)

        if self.latest_time_ms == self.time_captured_epoch_ms:
            self.bytes_per_ms = np.sum(self.packet_list)
        else:
            self.bytes_per_ms = np.sum(self.packet_list) / (self.latest_time_ms - self.time_captured_epoch_ms)

        self.variance_in_distribution = np.var(self.packet_list)
        self.total_packets_in_session = len(self.packet_list)
        self.total_duration_in_session_ms = self.latest_time_ms - self.time_captured_epoch_ms


def parse_packets(capture):

    global protocol_used
    try:
        pkt_protocols = capture[0].frame_info.protocols
        protocol = determine_protocol(pkt_protocols)
        if protocol == 0:
            # bluetooth
            protocol_used = 'b'
        elif protocol == 1:
            # zigbee
            protocol_used = 'z'
        elif protocol == 2 or protocol == 3:
            # wlan
            protocol_used = 'w'
    except:
        print('Error accessing packet #0.')
        return

    try:
        for packet in capture:
            
            # may remove this check later, as it still includes radio-tap/LL info
            # TCP or UDP indicate LAN data in WiFI.. NOT 802.11 ethernet traffic.
            # if (find_in_string(packet.frame_info.protocols, "tcp") or find_in_string(packet.frame_info.protocols, "udp")) and protocol == 2:
            #     continue

            try:
                if protocol == 0:
                    # bluetooth
                    create_flow_table_from_bt_packet(packet)
                elif protocol == 1:
                    # zigbee
                    create_flow_table_from_zb_packet(packet)
                elif protocol == 2:
                    # wlan
                    create_flow_table_from_wf_packet(packet)
                elif protocol == 3:
                    # also wlan but unencrypted
                    create_flow_table_from_wf_packet(packet, isUnenc=True)
            except Exception as e:
                # Certain packets may not have the required attributes, so we skip
                #print(f'Excepted: {e}')
                #print(traceback.format_exc())
                pass
    except:
        pass
            

    print("Generating table...")
   
    flow_attribute_list = list()
    # Each entry is a separate "session" of a flow
    for flow in flow_list:
        flow.calculate_final_metrics()
        class_dict = {val: getattr(flow, val) for val in csv_header_names}
        flow_attribute_list.append(class_dict)

    ft = pd.DataFrame(flow_attribute_list, columns=csv_header_names)

    print(f"Saving flow table to {os.getcwd()}/{outfile_name}_vb.csv")
    ft.to_csv(f'{outfile_name}_vb.csv', index=False)


def create_flow_table_from_bt_packet(packet):
    
    bt_sa = None
    bt_da = None

    # if it is a broadcast, the only address available is an advertising address.
    # it it is a comm, the src is a scanning address and the dst is the advertising address

    try:
        # No scanning address is issued; instead it's broadcast.
        bt_sa = packet.btle.scanning_address
        bt_da = packet.btle.advertising_address
    except:
        bt_sa = packet.btle.advertising_address
        bt_da = "ff:ff:ff:ff:ff:ff" 

    bt_sa_oui = bt_sa[0:8]
    bt_da_oui = bt_da[0:8]

    cap_length_bytes = float(packet.captured_length)

    oui_key = (bt_sa, bt_da)
    reverse_oui_key = (bt_da, bt_sa)

    # slightly skewed
    curr_time_ms = float(packet.frame_info.time_epoch) * 1_000 

    compose_table_from_attributes(oui_key, reverse_oui_key, cap_length_bytes, curr_time_ms, bt_sa, bt_da, bt_sa_oui, bt_da_oui)


def create_flow_table_from_zb_packet(packet):

    
    zb_sa_2byte = None
    zb_da_2byte = None
    zb_sa_8byte = None

    try:
        zb_sa_2byte = packet.wpan.src16
    except:
        pass

    try:
        zb_da_2byte = packet.wpan.dst16
    except:
        pass

    try:
        zb_sa_8byte = packet.zbee_nwk.src64
        if zb_sa_2byte not in zb_two_byte_dict:
            zb_two_byte_dict[zb_sa_2byte] = zb_sa_8byte
    except:
        pass

    sa_oui = zb_sa_2byte
    da_oui = zb_da_2byte
    
    zb_sa = zb_sa_2byte
    zb_da = zb_da_2byte

    cap_length_bytes = float(packet.captured_length) 

    oui_key = (zb_sa, zb_da)
    reverse_oui_key = (zb_da, zb_sa)

    curr_time_ms = float(packet.frame_info.time_epoch) * 1_000 # convert to milliseconds

    compose_table_from_attributes(oui_key, reverse_oui_key, cap_length_bytes, curr_time_ms, zb_sa, zb_da, sa_oui, da_oui)


def create_flow_table_from_wf_packet(packet, isUnenc=False):

    # try:
    #     wlan_sa = packet.wlan.sa
    #     wlan_da = packet.wlan.da
    # except Exception as e:
    #     if isUnenc:
    #         wlan_sa = packet.eth.src
    #         wlan_da = packet.eth.dst
    #     else:
    #         raise e

    if not isUnenc:
        wlan_sa = packet.wlan.sa
        wlan_da = packet.wlan.da
    else:
        wlan_sa = packet.eth.src
        wlan_da = packet.eth.dst

    sa_oui = wlan_sa[0:8]
    da_oui = wlan_da[0:8]
    cap_length_bytes = 0.0
    if isUnenc == True:
        cap_length_bytes = float(packet.captured_length)
    else:
        cap_length_bytes = float(packet.captured_length)

    oui_key = (wlan_sa, wlan_da)
    reverse_oui_key = (wlan_da, wlan_sa)

    # slightly skewed
    curr_time_ms = float(packet.frame_info.time_epoch)

    compose_table_from_attributes(oui_key, reverse_oui_key, cap_length_bytes, curr_time_ms, wlan_sa, wlan_da, sa_oui, da_oui)


def compose_table_from_attributes(oui_key, reverse_oui_key, cap_length_bytes, curr_time_ms, sa, da, sa_oui, da_oui):

    #Flow table class initializer: (self, src_oui, src_mac, initial_packet_size, dst_oui, dst_mac, init_time_captured_epoch_sec) 

    # Flow table is represented as a list of the attributes per flow of packets.
    # flow_table_entry = None
    # if len(flow_list) == 0 or flow_list[-1].src_oui != sa_oui:
    flow_table_entry = FlowTableEntry(sa_oui, sa, cap_length_bytes, da_oui, da, curr_time_ms)
    flow_list.append(flow_table_entry)
    # return

    # if len(flow_list) > 0 and flow_list[-1].src_oui == sa_oui:
    #     flow_list[-1].packet_list.append(cap_length_bytes)
    #     flow_list[-1].update_time_with_cap_time(curr_time_ms)


    # if len(flow_list) > 0 and flow_list[-1].dst_oui == sa_oui and ((curr_time_ms*1_000) - flow_list[-1].latest_time_ms) <= FLOW_SEQUENCE_THRESHOLD:
    #     flow_list[-1].packet_list.append(cap_length_bytes)
    #     flow_list[-1].update_time_with_cap_time(curr_time_ms)
    # elif ((curr_time_ms*1_000) - flow_list[-1].latest_time_ms) > FLOW_SEQUENCE_THRESHOLD:
    #     flow_table_entry = FlowTableEntry(sa_oui, sa, cap_length_bytes, da_oui, da, curr_time_ms)
    #     flow_list.append(flow_table_entry)
    # else:
    #     flow_list[-1].packet_list.append(cap_length_bytes)
    #     flow_list[-1].update_time_with_cap_time(curr_time_ms)

    
def determine_protocol(pkt_protocols):
    if find_in_string(pkt_protocols, "bt") or find_in_string(pkt_protocols, "bluetooth") or find_in_string(pkt_protocols, "hci"):
        print("Protocol in packet capture: Bluetooth\n")
        return 0
    elif find_in_string(pkt_protocols, "zb") or find_in_string(pkt_protocols, "zigbee") or find_in_string(pkt_protocols,"zbee"):
        print("Protocol in packet capture: Zigbee\n")
        return 1
    elif find_in_string(pkt_protocols, "wlan_radio") or find_in_string(pkt_protocols, "radiotap"):
        print("Protocol in packet capture: 802.11 WLAN\n")
        return 2
    elif find_in_string(pkt_protocols, "eth") or find_in_string(pkt_protocols, "tcp") or find_in_string(pkt_protocols, "udp"):
        print("Protocol in packet capture: LAN Wi-Fi")
        return 3


def find_in_string(target_string, find_str):
    if target_string.find(find_str) >= 0:
        return True

    return False


def create_header_names():
    print("Generating CSV headers...")
    flow_table_entry_dummy = FlowTableEntry('dummy', 'dummy', 0.0, 'dummy2', 'dummy2', 0.0)

    csv_header_names = [var for var in dir(flow_table_entry_dummy) if not var[0] == '_' and not (var.startswith("get") or var.startswith("set") or var.startswith('update') or var == 'packet_list' or var == 'calculate_final_metrics')]

    return csv_header_names


file = ''
while True:

    file = input("Path to pcap: ")
    if os.path.exists(file):
        print()
        outfile_name = file.split('/')[-1].split(".")[0]
        break
    else:
        print(f"Path to {file} does not exist, try again.\n")

print(f"Reading capture file: {file}...")

csv_header_names = create_header_names()
csv_header_names.reverse()

net_flow_table = pd.DataFrame([], columns=csv_header_names)

try:

    in_cap = ps.FileCapture(file)
    parse_packets(in_cap)
    in_cap.close()

except Exception:
    print(traceback.format_exc())