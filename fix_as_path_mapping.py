import sys
from sys import argv,exit
from collections import defaultdict

import pattern_match
from treat_aspath import TraceInfo, treatMappingProblems

if __name__ == "__main__":

    if len(argv) != 4:
        usage_str = "Usage: python fix_as_path_mapping.py <traces mapped> "
        usage_str += "<as paths list> <fixed mapping file>"
        print(usage_str)
        exit()

    # get the list with as-paths for the pattern matching process
    as_paths_file = argv[2]
    f_a = open(as_paths_file, 'r')
    as_paths_list = []
    for line in f_a:
        as_paths_list.append(line.strip())
    f_a.close()

    traces_mapped_file = argv[1]
    output_file = argv[3]

    f_in = open(traces_mapped_file, 'r')
    f_out = open(output_file, 'w')
    for line in f_in:
        tokens = line.strip().split('\t')
        probe_id = tokens[0]
        timestamp = tokens[1]
        target = tokens[2]
        ip_path = tokens[3].split(',')
        as_path = tokens[4].split(',')

        trace_info = TraceInfo(as_path, ip_path)
        # fix traces problems
        treatMappingProblems(trace_info)
        # check for pattern matching the as-paths that
        # still have unknown hops
        new_as_path = pattern_match.checkTraceForMatching(trace_info, as_paths_list)

        l_str = probe_id + "\t" + timestamp + "\t" + target + "\t"
        l_str += ",".join(as_path) + "\t" + ",".join(new_as_path) + "\n"
        f_out.write(l_str)

    f_in.close()
    f_out.close()
