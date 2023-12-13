#!/usr/bin/env python3

### LAST OPENED & EDITED: Saturday August 28, 2022

# Tool: Version B - may be consolidated later when time permits. (Allows for multiple entries from flows thresholds)

import os
import sys
import pyshark as ps
import numpy as np
import pandas as pd
import itertools as it
import traceback


FLOW_SEQUENCE_THRESHOLD = 60_000 # threshold for distinct entire (one minute = 60,000 ms)

outfile_name = "packet_flow_out.csv"
protocol_used = ''

net_flow_table = None
sub_net_flow_table = dict()

packet_metric_keeper = dict()
bidir_packet_metric_keeper = dict()

csv_header_names = list()
zb_two_byte_dict = dict()


class MetricHelper:

    def __init__(self):
        self.total_duration_ms = 0
        self.min_ps = 0
        self.max_ps = 0
        self.mean_ps = 0
        self.stdev_ps = 0
        self.transmission_rate_ms = 0
        self.transmission_rate_bytes_ms = 0


class FlowPacket:

    def __init__(self, src_mac, src_oui, dst_mac, dst_oui, bidirectional_total_packets, bidirectional_total_bytes,
                src2dst_total_bytes, dst2src_total_bytes, src2dst_total_packets, dst2src_total_packets, 
                src2dst_first_seen_time_ms, dst2src_first_seen_time_ms):

        # Epoch time is formatted in milliseoncds since "linux inception"

        self.src_mac = src_mac
        self.src_oui = src_oui
        self.dst_mac = dst_mac
        self.dst_oui = dst_oui

        self.bidirectional_total_packets = bidirectional_total_packets
        self.bidirectional_total_bytes = bidirectional_total_bytes

        self.src2dst_total_bytes = src2dst_total_bytes
        self.dst2src_total_bytes = dst2src_total_bytes

        self.src2dst_total_packets = src2dst_total_packets
        self.dst2src_total_packets = dst2src_total_packets

        self.src2dst_min_ps = 0.0
        self.src2dst_max_ps = 0.0

        self.src2dst_mean_ps = 0.0
        self.src2dst_stdev_ps = 0.0
        self.src2dst_first_seen_time_ms = src2dst_first_seen_time_ms
        self.src2dst_last_seen_time_ms = src2dst_first_seen_time_ms
        self.src2dst_total_duration_ms = 0.0

        self.dst2src_min_ps = 0.0
        self.dst2src_max_ps = 0.0

        self.dst2src_mean_ps = 0.0
        self.dst2src_stdev_ps = 0.0
        self.dst2src_first_seen_time_ms = dst2src_first_seen_time_ms
        self.dst2src_last_seen_time_ms = 0.0
        self.dst2src_total_duration_ms = 0.0

        self.bidirectional_min_ps = 0.0
        self.bidirectional_max_ps = 0.0

        self.bidirectional_mean_ps = 0.0
        self.bidirectional_stdev_ps = 0.0
        self.bidirectional_total_duration_ms = 0.0

        self.src2dst_transmission_rate_ms = 0.0
        self.dst2src_transmission_rate_ms = 0.0
        self.bidirectional_transmission_rate_ms = 0.0

        self.src2dst_transmission_rate_bytes_ms = 0.0
        self.dst2src_transmission_rate_bytes_ms = 0.0
        self.bidirectional_transmission_rate_byte_ms = 0.0

        self.bidirectional_last_seen_time_ms = 0.0
        self.bidirectional_first_seen_time_ms = 0.0

        self.protocol = ''

    # Auxilliary methods to aid in code cleanup.
    def transfer_calculated_data_to_src2dst(self, metric_obj):
        self.src2dst_total_duration_ms = metric_obj.total_duration_ms
        self.src2dst_min_ps = metric_obj.min_ps
        self.src2dst_max_ps = metric_obj.max_ps
        self.src2dst_mean_ps = metric_obj.mean_ps
        self.src2dst_stdev_ps = metric_obj.stdev_ps
        self.src2dst_transmission_rate_ms = metric_obj.transmission_rate_ms
        self.src2dst_transmission_rate_bytes_ms = metric_obj.transmission_rate_bytes_ms

    def transfer_calculated_data_to_dst2src(self, metric_obj):
        self.dst2src_total_duration_ms = metric_obj.total_duration_ms
        self.dst2src_min_ps = metric_obj.min_ps
        self.dst2src_max_ps = metric_obj.max_ps
        self.dst2src_mean_ps = metric_obj.mean_ps
        self.dst2src_stdev_ps = metric_obj.stdev_ps
        self.dst2src_transmission_rate_ms = metric_obj.transmission_rate_ms
        self.dst2src_transmission_rate_bytes_ms = metric_obj.transmission_rate_bytes_ms

    def transfer_calculated_data_to_bidirec(self, metric_obj):
        self.bidirectional_total_duration_ms = metric_obj.total_duration_ms
        self.bidirectional_min_ps = metric_obj.min_ps
        self.bidirectional_max_ps = metric_obj.max_ps
        self.bidirectional_mean_ps = metric_obj.mean_ps
        self.bidirectional_stdev_ps = metric_obj.stdev_ps
        self.bidirectional_transmission_rate_ms = metric_obj.transmission_rate_ms
        self.bidirectional_transmission_rate_byte_ms = metric_obj.transmission_rate_bytes_ms



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
        elif protocol == 2:
            # wlan
            protocol_used = 'w'
    except:
        print('Error accessing packet #0.')
        return

    for packet in capture:
        
        # may remove this check later, as it still includes radio-tap/LL info
        # TCP or UDP indicate LAN data in WiFI.. NOT 802.11 ethernet traffic.
        if (find_in_string(packet.frame_info.protocols, "tcp") or find_in_string(packet.frame_info.protocols, "udp")) and protocol == 2:
            continue

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
        except Exception:
            # Certain packets may not have the required attributes, so we skip
            pass
            

    print("Generating table...")
   
    # Each entry is a (source, dest) or (dest, source) tuple pair.
    for entry in sub_net_flow_table.keys():

        flow_packet = sub_net_flow_table[entry]

        src_oui_key = entry
        reverse_oui_key = (entry[1], entry[0])

        #src2dst
        if (src_oui_key in packet_metric_keeper) and (len(packet_metric_keeper[src_oui_key]) > 0):
            
            execute_src2dst_attributes(flow_packet, src_oui_key)

        #dst2src
        if (reverse_oui_key in packet_metric_keeper) and (len(packet_metric_keeper[reverse_oui_key]) > 0):

            execute_dst2src_bidir_attributes(flow_packet,reverse_oui_key)

    
    # concatenates final lists and pushes out the updated one.
    sub_flow_table_list = create_dataframe_from_flowtable(sub_net_flow_table)
    
    # Save the flow table to a CSV file.
    global net_flow_table
    net_flow_table = net_flow_table.append(sub_flow_table_list)
    
    print(f"Saving flow table to {os.getcwd()}/{outfile_name}_vb.csv")
    net_flow_table.to_csv(f'{outfile_name}_vb.csv', index=False)


def create_dataframe_from_flowtable(flow_table):
    packet_attribute_list = list()
    for packet in flow_table.values():
        class_dict = {val: getattr(packet, val) for val in csv_header_names}
        packet_attribute_list.append(class_dict)
    
    # Save the flow table to a CSV file.
    ft = pd.DataFrame(packet_attribute_list, columns=csv_header_names)
    return ft

def calculate_quantitative_attributes_from_packet_entry(first_seen_time_ms, last_seen_time_ms, total_packets, total_bytes, packet_list):

    metric_obj = MetricHelper()

    metric_obj.total_duration_ms = (last_seen_time_ms - first_seen_time_ms)

    if len(packet_list) > 0:
        metric_obj.min_ps = np.min(packet_list)
        metric_obj.max_ps = np.max(packet_list)
        metric_obj.mean_ps = np.mean(packet_list)
        metric_obj.stdev_ps = np.std(packet_list)
    else:
        metric_obj.min_ps = 0
        metric_obj.max_ps = 0
        metric_obj.mean_ps = 0
        metric_obj.stdev_ps = 0

    if metric_obj.total_duration_ms > 0:
        metric_obj.transmission_rate_ms = (total_packets / metric_obj.total_duration_ms)
        metric_obj.transmission_rate_bytes_ms = (total_bytes / metric_obj.total_duration_ms)
    else:
        metric_obj.transmission_rate_ms = total_packets
        metric_obj.transmission_rate_bytes_ms = total_bytes

    return metric_obj


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


def create_flow_table_from_wf_packet(packet):

    wlan_sa = packet.wlan.sa
    wlan_da = packet.wlan.da

    sa_oui = wlan_sa[0:8]
    da_oui = wlan_da[0:8]

    cap_length_bytes = float(packet.captured_length)

    oui_key = (wlan_sa, wlan_da)
    reverse_oui_key = (wlan_da, wlan_sa)

    # slightly skewed
    curr_time_ms = float(packet.frame_info.time_epoch) * 1_000 

    compose_table_from_attributes(oui_key, reverse_oui_key, cap_length_bytes, curr_time_ms, wlan_sa, wlan_da, sa_oui, da_oui)


def compose_table_from_attributes(oui_key, reverse_oui_key, cap_length_bytes, curr_time_ms, sa, da, sa_oui, da_oui):

    # dst2src - or the case where they talk to themselves
    if ((oui_key not in sub_net_flow_table) and (reverse_oui_key in sub_net_flow_table)) or ((oui_key in sub_net_flow_table) and (reverse_oui_key == oui_key)):

        flow_packet = sub_net_flow_table[reverse_oui_key]
        flow_packet.dst2src_total_bytes += cap_length_bytes
        flow_packet.dst2src_total_packets += 1

        if flow_packet.dst2src_first_seen_time_ms == 0:
            flow_packet.dst2src_first_seen_time_ms = curr_time_ms

        # time elapsed from when this entry was last seen
        time_elapsed = (curr_time_ms - flow_packet.dst2src_last_seen_time_ms)

        flow_packet.dst2src_last_seen_time_ms = curr_time_ms

        #The reason OUI key is used here is because this is the dst2src in the flow table, but in the metric keeper we index by this key. 
        if oui_key not in packet_metric_keeper:
            packet_metric_keeper[oui_key] = list()

        if oui_key not in bidir_packet_metric_keeper:
            bidir_packet_metric_keeper[oui_key] = list()


        packet_metric_keeper[oui_key].append(cap_length_bytes)
        bidir_packet_metric_keeper[oui_key].append(cap_length_bytes)

        most_recent_src2dst_cap_len = packet_metric_keeper[reverse_oui_key][-1]
        bidir_packet_metric_keeper[oui_key].append(most_recent_src2dst_cap_len)


        # If threshold exceeded, flush from sub & packets and place in netflowtable.
        if time_elapsed >= FLOW_SEQUENCE_THRESHOLD:
            execute_dst2src_bidir_attributes(flow_packet, oui_key)
            save_entry_and_flush_sub_table(flow_packet, packet_metric_keeper, bidir_packet_metric_keeper, oui_key, sa, sa_oui, da, da_oui, cap_length_bytes, curr_time_ms)
        
        return


    # Not in table at all, initialize
    if (oui_key not in sub_net_flow_table) and (reverse_oui_key not in sub_net_flow_table):
        initialize_entry(oui_key, sa, sa_oui, da, da_oui, cap_length_bytes, curr_time_ms)
        return


    # src2dst - the oui is in table and reverse is NOT in table.
    flow_packet = sub_net_flow_table[oui_key]
    flow_packet.src2dst_total_bytes += cap_length_bytes

    #todo: elaborate on this part: depends on which entry was actually last seen.
    time_elapsed = (curr_time_ms - flow_packet.src2dst_last_seen_time_ms)

    flow_packet.src2dst_last_seen_time_ms = curr_time_ms
    flow_packet.src2dst_total_packets += 1
    packet_metric_keeper[oui_key].append(cap_length_bytes)

    # If threshold exceeded, flush from sub & packets and place in netflowtable.
    if (oui_key in sub_net_flow_table) and (time_elapsed >= FLOW_SEQUENCE_THRESHOLD):
        
        execute_src2dst_attributes(flow_packet, oui_key)
        save_entry_and_flush_sub_table(flow_packet, packet_metric_keeper, bidir_packet_metric_keeper, oui_key)
        

def save_entry_and_flush_sub_table(flow_packet, packet_metric_keeper, bidir_packet_metric_keeper, oui_key):
    
    global net_flow_table

    # save old entry into netflowtable
    packet_attribute_list = list()
    class_dict = {val: getattr(flow_packet, val) for val in csv_header_names}
    
    packet_attribute_list.append(class_dict)

    ft = pd.DataFrame(packet_attribute_list, columns=csv_header_names)
    net_flow_table = net_flow_table.append(ft)
    
    # flush from table and metric keepers
    packet_metric_keeper[oui_key] = list()
    bidir_packet_metric_keeper[oui_key] = list()
    sub_net_flow_table.pop(oui_key)




def initialize_entry(oui_key, sa, sa_oui, da, da_oui, cap_length_bytes, curr_time_ms):

    flow_packet = FlowPacket(sa, sa_oui, da, da_oui, 0, 0, cap_length_bytes, 0, 1, 0, curr_time_ms, 0)
    flow_packet.protocol = protocol_used
    sub_net_flow_table[oui_key] = flow_packet


    if oui_key not in packet_metric_keeper:
        packet_metric_keeper[oui_key] = list()

    packet_metric_keeper[oui_key].append(cap_length_bytes)


def execute_src2dst_attributes(flow_packet, src_oui_key):
    
    src2dst_packet_list = packet_metric_keeper[src_oui_key]
    metric_obj = calculate_quantitative_attributes_from_packet_entry(flow_packet.src2dst_first_seen_time_ms, 
                            flow_packet.src2dst_last_seen_time_ms, 
                            flow_packet.src2dst_total_packets, 
                            flow_packet.src2dst_total_bytes, 
                            src2dst_packet_list)

    flow_packet.transfer_calculated_data_to_src2dst(metric_obj)


def execute_dst2src_bidir_attributes(flow_packet, reverse_oui_key):


    dst2src_packet_list = packet_metric_keeper[reverse_oui_key]

    bidir_packet_list = None
    if reverse_oui_key in bidir_packet_metric_keeper:
        bidir_packet_list = bidir_packet_metric_keeper[reverse_oui_key]
    else:
        bidir_packet_list = []
            

    metric_obj_dst2src = calculate_quantitative_attributes_from_packet_entry(flow_packet.dst2src_first_seen_time_ms, 
                            flow_packet.dst2src_last_seen_time_ms, 
                            flow_packet.dst2src_total_packets, 
                            flow_packet.dst2src_total_bytes, 
                            dst2src_packet_list)

    flow_packet.transfer_calculated_data_to_dst2src(metric_obj_dst2src)

    flow_packet.bidirectional_total_bytes = (flow_packet.src2dst_total_bytes + flow_packet.dst2src_total_bytes)
    flow_packet.bidirectional_total_packets = (flow_packet.src2dst_total_packets + flow_packet.dst2src_total_packets)
    flow_packet.bidirectional_first_seen_time_ms = flow_packet.src2dst_first_seen_time_ms

    if flow_packet.dst2src_last_seen_time_ms < flow_packet.src2dst_last_seen_time_ms:
        flow_packet.bidirectional_last_seen_time_ms = flow_packet.src2dst_last_seen_time_ms
    else:
        flow_packet.bidirectional_last_seen_time_ms = flow_packet.dst2src_last_seen_time_ms
                    

    metric_obj_bidirectional = calculate_quantitative_attributes_from_packet_entry(flow_packet.bidirectional_first_seen_time_ms, 
                            flow_packet.bidirectional_last_seen_time_ms, 
                            flow_packet.bidirectional_total_packets, 
                            flow_packet.bidirectional_total_bytes,
                            bidir_packet_list)

    flow_packet.transfer_calculated_data_to_bidirec(metric_obj_bidirectional)

    
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


def find_in_string(target_string, find_str):
    if target_string.find(find_str) >= 0:
        return True

    return False


def create_header_names():
    print("Generating CSV headers...")
    flow_packet = FlowPacket(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    csv_header_names = [var for var in dir(flow_packet) if not var[0] == '_' and not var.startswith("transfer")]
    
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