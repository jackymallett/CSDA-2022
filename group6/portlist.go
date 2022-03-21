// Portlist defines a new type portlist and defines how to parse it using the
// flag package.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
)

// Convert a port in a string format to integer safely.
func portToInt(ps string) int {
	if p, err := strconv.Atoi(ps); err == nil {
		// If no error when converting then return the integer representation.
		return p
	} else {
		// Else report the error.
		log.Printf("error parsing port %q\n", ps)
		log.Printf("\t%v\n", err)
		return -1
	}
}

type portlist []int

// Defines how the flag package should represent portlist as a string.
func (pl *portlist) String() string {
	return fmt.Sprint(*pl)
}

// Defines how the flag package should parse a portlist variable given on the
// command line.
// A single port should not be changed by a port range should be "flattened".
// That is, every port in the specified range should be explicitly listed.
func (pl *portlist) Set(portfilename string) error {
	// We do not allow two -p flags at the same time.
	if len(*pl) > 0 {
		return errors.New("Ports already set")
	}

	// We expect to get a name of a file containing the port ranges to scan,
	// separated by newline.
	portfile, err := os.Open(portfilename)
	if err != nil {
		log.Fatal(err)
	}
	defer portfile.Close()

	// Read each port range from the file.
	scanner := bufio.NewScanner(portfile)
	for scanner.Scan() {
		portrange := scanner.Text()
		// If a port range contains no -, then assume that it is a single port
		// number. If it contains a single -, then assume it is a port range.
		// Otherwise, it is unrecognized.
		switch strings.Count(portrange, "-") {
		case 0:
			// If a single port, then convert from string to integer. If the
			// port is malformed then we exit.
			if p := portToInt(portrange); p != -1 {
				*pl = append(*pl, p)
			} else {
				os.Exit(1)
			}
		case 1:
			// If a port range, then extract the start and end of the range. If
			// either portfilename is malformed then we exit.
			portpoints := strings.Split(portrange, "-")
			startPort := portToInt(portpoints[0])
			endPort := portToInt(portpoints[1])
			if startPort == -1 || endPort == -1 {
				os.Exit(1)
			}
			// Extract each port in range.
			for p := startPort; p <= endPort; p++ {
				*pl = append(*pl, p)
			}
		default:
			log.Fatalf("unrecognized port format %q\n", portrange)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return nil
}
