import sys, re, copy
import json
from sys import argv,exit
from collections import defaultdict

import pattern_match

class TraceInfo():
    def __init__(self, as_path, ip_path):
        self.as_path = as_path
        self.ip_path = ip_path
        self.h_count = [1 for x in as_path]

# functions to treat as-path anomalies

def replaceUnknownByX(trace_info):
    unknown_hops = ['rv','nm','x']
    new_as_path = []
    for asn in trace_info.as_path:
        if asn in unknown_hops:
            new_as_path.append('x')
        else:
            new_as_path.append(asn)
    trace_info.as_path = new_as_path

# replace multiple occurrences (in sequence) of a same ASN for only one
def removeMultipleOccurrences(trace_info):
    previous_hop = -1
    to_disconsider = []
    new_as_path = []
    new_h_count = []
    count = 1
    for asn in trace_info.as_path:
        if asn in to_disconsider:
            new_as_path.append(asn)
            previous_hop = asn
            new_h_count.append(1)
            continue
        if asn == previous_hop:
            new_h_count[-1] += 1
            continue
        new_as_path.append(asn)
        previous_hop = asn
        new_h_count.append(1)

    trace_info.as_path = new_as_path
    trace_info.h_count = new_h_count


# remove unknown hop between two hops of a same AS, e.g., AS1,x/rv/nm,AS1 for just AS1
def removeUnknownHopBtwAS(trace_info):
    previous_hop = -1
    skip_flag = 0
    unknown_hops = ['rv','nm','x']
    new_as_path = []
    new_ip_path = []
    new_h_count = []
    ip_index = 0
    for vindex in range(len(trace_info.as_path)):
        if skip_flag == 1:
            skip_flag = 0
            previous_hop = trace_info.as_path[vindex]

            for i in range(trace_info.h_count[vindex]):
                new_ip_path.append(trace_info.ip_path[ip_index])
                ip_index += 1

            new_h_count[-1] += trace_info.h_count[vindex]
            continue
        if trace_info.as_path[vindex] in unknown_hops:
            if vindex == len(trace_info.as_path)-1:
                new_h_count.append(trace_info.h_count[vindex])
                new_ip_path.append(trace_info.ip_path[vindex])
                new_as_path.append(trace_info.as_path[vindex])
                continue
            if previous_hop == trace_info.as_path[vindex+1]:
                skip_flag = 1
                previous_hop = trace_info.as_path[vindex]
                ip_index += 1
                continue
            new_as_path.append(trace_info.as_path[vindex])

            for i in range(trace_info.h_count[vindex]):
                new_ip_path.append(trace_info.ip_path[ip_index])
                ip_index += 1

            new_h_count.append(trace_info.h_count[vindex])
            previous_hop = trace_info.as_path[vindex]
            continue
        new_as_path.append(trace_info.as_path[vindex])


        for i in range(trace_info.h_count[vindex]):
            new_ip_path.append(trace_info.ip_path[ip_index])
            ip_index += 1

        new_h_count.append(trace_info.h_count[vindex])
        previous_hop = trace_info.as_path[vindex]

    trace_info.as_path = new_as_path
    trace_info.ip_path = new_ip_path
    trace_info.h_count = new_h_count

# remove unknown hops from the beginning; it does not harm correctness
def removeInitialUnknownHops(trace_info):
    unknown_hops = ['rv','nm','x']
    new_as_path = []
    initial_flag = 0
    for asn in trace_info.as_path:
        if asn in unknown_hops:
            if initial_flag == 0:
                for i in range(trace_info.h_count[0]):
                    trace_info.ip_path.pop(0)
                trace_info.h_count.pop(0)
                continue
            else:
                new_as_path.append(asn)
        else:
            initial_flag = 1
            new_as_path.append(asn)

    trace_info.as_path = new_as_path

'''
It gets the list of ASes that are IXPs informed by CAIDA (as-rel file).
'''
def getIxpList():
    ixp_list_path = "data/ixp_list.txt"
    ixp_list_file = open(ixp_list_path, 'r')
    ixp_list = []

    for line in ixp_list_file:
        ixp = line.strip()
        ixp_list.append(ixp)

    ixp_list_file.close()

    return ixp_list


'''
It removes the remaining IXPs' ASes.
'''
def removeIXPs(trace_info, ixp_list):
    new_ip_path = []
    new_as_path = []
    new_h_count = []
    for i in range(0,len(trace_info.as_path)):
        curr_as = trace_info.as_path[i]
        curr_ip = trace_info.ip_path[i]
        curr_h_count = trace_info.h_count[i]
        if curr_as in ixp_list:
            continue
        else:
            new_as_path.append(curr_as)
            new_ip_path.append(curr_ip)
            new_h_count.append(curr_h_count)

    trace_info.ip_path = new_ip_path
    trace_info.as_path = new_as_path
    trace_info.h_count = new_h_count


# treat
def treatMappingProblems(trace_info):
    ixp_list = getIxpList()

    replaceUnknownByX(trace_info)
    removeMultipleOccurrences(trace_info)
    removeUnknownHopBtwAS(trace_info)
    removeInitialUnknownHops(trace_info)
    removeIXPs(trace_info, ixp_list)


if __name__ == "__main__":

    trace_info = TraceInfo(['1','2','x','3','3','x','3','4','1200','47065','5'],[1,2,10,3,4,5,6,7,8,10,9])

    treatMappingProblems(trace_info)

    # check for pattern matching
    as_paths_list = []
    as_paths_list.append(",".join(['2','3','4','47065','5']))
    new_as_path = pattern_match.checkTraceForMatching(trace_info, as_paths_list)




