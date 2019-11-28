import radix
from sys import argv, exit
from os.path import exists
from collections import defaultdict

from config import ASN_MAPPING_DB, RESERVED_PREFIXES
import whois_cymru

class IPtoAS():
    def __init__(self, current_db_file):
        self.db = radix.Radix()
        reserved_f = open(RESERVED_PREFIXES, "r")
        for line in reserved_f:
            tokens = line.split()
            if (len(tokens) != 2):
                continue
            prefix = tokens[0].strip()
            asn = tokens[1].strip()
            node = self.db.add(prefix)
            node.data['asn'] = asn
        reserved_f.close()

        if not exists(current_db_file):
            f_tmp = open(current_db_file, 'w')
            f_tmp.close()

        f = open(current_db_file, "r")
        for line in f:
            tokens = line.split()
            if (len(tokens) != 2):
                continue
            prefix = tokens[0]
            asn = tokens[1]
            node = self.db.add(prefix)
            node.data['asn'] = asn
        f.close()

    def addNewNode(self, prefix, asn):
        node = self.db.add(prefix)
        node.data['asn'] = asn

    def mapIPtoAS(self, ip):
        node = self.db.search_best(ip)
        try:
            return node.data['asn']
        except AttributeError:
            return "0"

    def exportDatabase(self, filename):
        f = open(filename, "w")
        nodes = self.db.nodes()
        for node in nodes:
            fline = node.prefix + " " + str(node.data['asn']) + "\n"
            f.write(fline)
        f.close()

    '''
    Get the set of unique IP addresses from all traceroutes collected
    in a specific round by ripe atlas plataform.
    '''
    def getUniqueIPs(self, traces_file):
        f = open(traces_file, "r")
        unique_ips = set()
        for line in f:
            tokens = line.split()
            if (len(tokens) != 4):
                continue
            hops = tokens[3].split("|")
            for hop in hops:
                ip = hop.split(",")[0]
                unique_ips.add(ip)

        return list(unique_ips)


    def findMissingPrefixes(self, ips):
        ips_without_mapping = []
        for ip in ips:
            try:
                if (self.mapIPtoAS(ip) == "0"):
                    ips_without_mapping.append(ip)
            except ValueError:
                continue
        return ips_without_mapping


    def includeNewPrefixes(self, query_result):
        ips_infos = query_result.split("\n")
        for ip_info in ips_infos:
            tokens = ip_info.split("|")
            if (len(tokens) != 3):
                continue
            asn = tokens[0].strip()
            ip = tokens[1].strip()
            desc = tokens[2]

            try:
                if (self.mapIPtoAS(ip) == "0"):
                    if (asn != "NA"):
                        preparing_prefix = ip.split(".")
                        prefix = ".".join(preparing_prefix[0:3]) + ".0/24"
                        self.addNewNode(prefix, asn)
            except ValueError:
                continue


    def traceParser(self, traceroute):
        tokens = traceroute.split()
        if (len(tokens) != 4):
            return "None"
        if tokens[3].split(",")[0] == '-1':
            return "None"

        probe_id = tokens[0]
        timestamp = tokens[1]
        target = tokens[2]
        trace = tokens[3].split("|")

        hops = []
        for host in trace:
            hops.append(host.split(",")[0])

        hops_list = []
        for hop in hops:
            if (hop == "*"):
                hops_list.append("x")
            else:
                as_num = self.mapIPtoAS(hop)
                if (as_num == "0"):
                    hops_list.append("nm")
                else:
                    hops_list.append(as_num)
        as_path = ",".join(hops_list)
        ip_path = ",".join(hops)

        return [probe_id, timestamp, target, as_path, ip_path]

    def mapTraces(self, traces_file, output_file):

        f_out = open(output_file, 'w')

        f = open(traces_file, "r")
        for line in f:
            parsed_trace = self.traceParser(line.strip())
            #print parsed_trace
            if (parsed_trace == "None"):
                continue

            probe_id, timestamp, target, as_path, ip_path = parsed_trace

            line_str = str(probe_id) + "\t" + str(timestamp) + "\t"
            line_str += target + "\t" + ip_path + "\t" + as_path + "\n"

            f_out.write(line_str)

        f.close()

        f_out.close()



if __name__ == "__main__":

    if len(argv) != 3:
        print("Usage: python map_ip_to_as.py <traces file> <file with mapped traces>")
        exit()

    traces_file = argv[1]
    output_file = argv[2]

    ip_to_as = IPtoAS(ASN_MAPPING_DB)
    unique_ips = ip_to_as.getUniqueIPs(traces_file)
    unmapped_ips = ip_to_as.findMissingPrefixes(unique_ips)
    query_result = whois_cymru.getInfo(unmapped_ips)
    ip_to_as.includeNewPrefixes(query_result)
    ip_to_as.exportDatabase(ASN_MAPPING_DB)
    ip_to_as.mapTraces(traces_file, output_file)




