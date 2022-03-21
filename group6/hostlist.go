// Hostlist provides functionality to process a list of hostnames, IP addresses,
// or a CIDR specification of IP addresses.
package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
)

type hostlist []string

// Defines how the flag package should represent hostlist as a string.
func (hl *hostlist) String() string {
	return fmt.Sprint(*hl)
}

// Defines how the flag package should parse a hostlist variable given on the
// command line.
// IP addresses and hostnames should not be changed but a CIDR specification of
// IP addresses should be "flattened". That is, every IP address in the
// specified range (except the network and broadcast address) should be
// explicitly listed.
func (hl *hostlist) Set(hostfilename string) error {
	// We do not allow two -h flags at the same time.
	if len(*hl) > 0 {
		return errors.New("Hosts already set")
	}

	// We expect to get a name of a file containing the IP addresses/CIDR
	// specifications to scan, separated by newline.
	hostfile, err := os.Open(hostfilename)
	if err != nil {
		log.Fatal(err)
	}
	defer hostfile.Close()

	// Read each IP address/CIDR specification from the file.
	scanner := bufio.NewScanner(hostfile)
	for scanner.Scan() {
		host := scanner.Text()
		// We assume that hostnames and IP addresses do not contain a /, CIDR
		// specifications include exactly one /, and everything else is
		// unrecognized.
		switch strings.Count(host, "/") {
		case 0:
			// Do not modify hostnames and IP addresses.
			*hl = append(*hl, host)
		case 1:
			// Convert CIDR specification into an IPNet struct.
			_, ipv4Net, err := net.ParseCIDR(host)
			if err != nil {
				log.Fatal(err)
			}

			// Extract the subnet mask and network IP as binary numbers. The
			// network IP is the first IP address in the CIDR range (has all the
			// host bits set to 0), the broadcast IP is the final IP address in
			// the CIDR range (has all the host bits set to 1). To get the
			// broadcast IP we can use the subnet mask inverted to set all the
			// host bits of the network IP to 1.

			// CIDR range    : 192.168.1.17/29
			// IP address    : 11000000.10101000.00000001.00010001
			// Mask          : 11111111.11111111.11111111.11111000
			// Network IP    : 11000000.10101000.00000001.00010000 = IP address & Mask
			// Inverted Mask : 00000000.00000000.00000000.00000111
			// Broadcast IP  : 11000000.10101000.00000001.00010111 = Network IP | Inverted Mask
			mask := binary.BigEndian.Uint32(ipv4Net.Mask)
			networkIP := binary.BigEndian.Uint32(ipv4Net.IP)
			broadcastIP := networkIP | (mask ^ 0xFFFFFFFF)

			// Now that we have the first IP in the CIDR range (network IP) and
			// the last (broadcast IP) we can extract all the IP addresses in
			// between.
			for i := networkIP + 1; i <= broadcastIP-1; i++ {
				ip := make(net.IP, 4)
				binary.BigEndian.PutUint32(ip, i)
				*hl = append(*hl, ip.String())
			}
		default:
			log.Fatalf("unrecognized host format %q\n", host)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return nil
}
