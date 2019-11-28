# ip_to_as

### Execution
```
Usage: python map_ip_to_as.py [1] [2]
```
```
[1] file with traceroutes
format: 
- it uses the traceroute format received from Ripe Altas
- one traceroute per line
- probe_id \t timestamp \t target \t traceroute_information
- the file "input_example.txt" shows how it is organized
```
```
[2] file with the traceroutes mapped
format:
- one traceroute per line
- probe_id \t timestamp \t target \t IP-path \t AS-path
- the file "output_example.txt" shows how it is organized
