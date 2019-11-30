# ip_to_as

### Execution of IP to AS mapping
```
Usage: python map_ip_to_as.py [1] [2]
```
```
[1] file with traceroutes
format: 
- it uses the traceroute format received from Ripe Altas
- one traceroute per line
- probe_id \t timestamp \t target \t traceroute_information
- the file "data/input_example.txt" shows how it is organized
```
```
[2] file with the traceroutes mapped
format:
- one traceroute per line
- probe_id \t timestamp \t target \t IP-path \t AS-path
- the file "data/output_example.txt" shows how it is organized
```

### Execution of heuristics to fix as-path issues

```
Usage: python fix_as_path_mapping.py [1] [2] [3]
```
```
[1] file with the traceroutes already mapped
*it uses the output file of IP to AS mapping execution
format:
- one traceroute per line
- probe_id \t timestamp \t target \t IP-path \t AS-path
- the file "data/output_example.txt" shows how it is organized

```
```
[2] file with the as-paths list to use in the pattern matching process
format:
- one as-path per line
- e.g., 1916,3356,47065
- the file "as_paths_list.txt" shows how it is organized
```
```
[3] file with the fixed mapping
- probe_id \t timestamp \t target \t original AS-path \t fixed AS-path
- the file "data/fixed_mapped.txt" shows how it is organized
```




