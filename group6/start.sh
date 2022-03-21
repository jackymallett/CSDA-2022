#!/bin/bash

go build . && ./iceland_scanner -hosts hostlist.txt -ports top_1000_ports.txt && ./iceland_scanner -known-open -ports all_ports_minus_top_1000.txt && ./iceland_scanner -vuln-scan
