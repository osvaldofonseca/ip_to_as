import sys, os, re, copy
from sys import argv,exit
from collections import defaultdict


# start the as-path one hop before the first x
def createPatternText(as_path, h_count):
    unknown_hops = ['rv','nm','x']
    fx_flag = 0
    pattern_txt = ""
    first_pattern_index = 0
    for vindex in range(len(as_path)):
        if as_path[vindex] in unknown_hops:
            if fx_flag == 0:
                fx_flag = 1
                pattern_txt += as_path[vindex-1]
                first_pattern_index = vindex-1
            max_hops = h_count[vindex]
            pattern_txt += "(,[0-9]+){0," + str(max_hops) + "}"
        else:
            if fx_flag == 0:
                continue
            if pattern_txt == "":
                pattern_txt += as_path[vindex]
            else:
                pattern_txt += "," + as_path[vindex]
    pattern_txt += "$"

    return (pattern_txt, first_pattern_index)


# receive a regex and return the list of matches
def tryMatch(pattern_txt, items_to_match):
    pattern = re.compile(pattern_txt)

    p_results = []
    for item in items_to_match:
        regex_result = pattern.search(item)
        if regex_result:
            p_results.append(regex_result.group())

    return p_results


# check trace pattern matching
def checkTraceForMatching(trace_info, as_paths_list):

    as_path = trace_info.as_path
    h_count = trace_info.h_count

    # check if the mapped trace has at least one unknown hop
    if 'x' in as_path:

        pattern_txt, first_pattern_index = createPatternText(as_path, h_count)

        # try to match with as-paths list
        p_results = tryMatch(pattern_txt, as_paths_list)

        if len(p_results) == 0:

            # found no match
            new_as_path = as_path

        else:
            # found at least one match with as-paths list
            candidates = [(len(cap.split(',')),cap) for cap in set(p_results)]
            candidates.sort()
            new_as_path = as_path[:first_pattern_index]+candidates[0][1].split(",")

    # the as-path does not have any unknown hop
    else:
        new_as_path = as_path

    return new_as_path



