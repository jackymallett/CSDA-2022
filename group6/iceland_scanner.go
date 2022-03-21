// Scanner takes a list of hosts and a list of ports and checks which
// combinations are open.
package main

import (
	"database/sql"
	"flag"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	MAX_CONCURRENT_SCANS  = 256
	MIN_SLEEP_TIME_MS     = 500
	MAX_SLEEP_TIME_MS     = 1000
	SQLITE3_DATABASE_PATH = "./scan.db"
	CREATE_TABLE_QUERY    = `
CREATE TABLE IF NOT EXISTS scan_results (id INTEGER PRIMARY KEY AUTOINCREMENT, host_ip TEXT NOT NULL,
port_number INTEGER NOT NULL, timestamp DATETIME NOT NULL, open INTEGER NOT NULL, nmap_output TEXT)`
	INSERT_TABLE_QUERY = `
INSERT INTO scan_results(host_ip, port_number, timestamp, open, nmap_output) VALUES(?, ?, ?, ?, ?)
`
)

type ScanResult struct {
	hostIP     string
	portNumber int
	timestamp  time.Time
	open       bool
	nmapOutput string
}

// printerWg makes sure that we don't exit until we have gotten results from all
// host:port combinations.
var printerWg = &sync.WaitGroup{}

// scanHostWg makes sure that we don't exit until we have scanned every host:port.
var scanHostWg = &sync.WaitGroup{}

// scanPort scans a single host:port combination. If vuln-scan is true then try
// to use nmap to do version discovery on the port, else just try to connect to
// the port.
func scanPort(host string, port int, vuln_scan bool) (string, error) {
	if vuln_scan {
		nmapOutput, err := exec.Command("/usr/bin/nmap", "--script", "vuln", host, "-p", strconv.Itoa(port), "-T2").Output()
		return string(nmapOutput), err
	} else {
		hostport := net.JoinHostPort(host, strconv.Itoa(port))
		_, err := net.DialTimeout("tcp", hostport, time.Second)
		return "", err
	}
}

// scanHost scan every port in portlist on host and reports which are open and
// which are closed. Everything that is not open is assumed to be closed.
func scanHost(host string, ports_p *portlist, ch chan<- ScanResult, vuln_scan bool) {
	defer scanHostWg.Done()
	for _, port := range *ports_p {
		// Decide how long to sleep for before trying next port. Will sleep
		// between MIN_SLEEP_TIME_MS and MAX_SLEEP_TIME_MS milliseconds.
		sleeptime := MIN_SLEEP_TIME_MS + rand.Float64()*(MAX_SLEEP_TIME_MS-MIN_SLEEP_TIME_MS)
		// Try scanning the host:port until we get that either the port is open or
		// closed. Sleep and try again if we have too many open files.
		for done := false; !done; {
			// Scan a host:port combination. nmapOutput will only be set if
			// vuln-scan is true.
			nmapOutput, err := scanPort(host, port, vuln_scan)
			// If no error then the scan was successful.
			// TODO: Just because nmap does not set err does not mean that the
			// port is open. It just mean that nmap didn't fail.
			if err == nil {
				ch <- ScanResult{host, port, time.Now(), true, nmapOutput}
				done = true
			} else if !strings.Contains(err.Error(), "socket: too many open files") &&
				!strings.Contains(err.Error(), "bind: An operation on a socket") {
				// If we got either error then we have too many sockets open but
				// don't know if the host:port is opened or closed. If we got
				// another error then the host:port is most likely closed.
				ch <- ScanResult{host, port, time.Now(), false, ""}
				done = true
			} else {
				log.Println(err)
			}
		}
		time.Sleep(time.Duration(sleeptime) * time.Millisecond)
	}
	return
}

func scanHostsPorts(hosts_p *hostlist, ports_p *portlist) {
	//////////////////////////////////////////
	// Scan every combination of host:port. //
	//////////////////////////////////////////
	// We create a string channel so that printer can do all the printing. This
	// ensures that the output from each goroutine is processed as a unit, and
	// prevents any unexpected outout if two goroutines finish at the same time.
	printerCh := make(chan ScanResult)
	printerWg.Add(1)
	go printer(printerCh)

	// Shuffle hosts to avoid IDS that monitor multiple hosts.
	rand.Shuffle(len(*hosts_p), func(i int, j int) {
		(*hosts_p)[i], (*hosts_p)[j] = (*hosts_p)[j], (*hosts_p)[i]
	})
	// Shuffle ports to avoid IDS that monitors requests to sequential port
	// numbers.
	rand.Shuffle(len(*ports_p), func(i int, j int) {
		(*ports_p)[i], (*ports_p)[j] = (*ports_p)[j], (*ports_p)[i]
	})

	sem := make(chan interface{}, MAX_CONCURRENT_SCANS)
	for i, host := range *hosts_p {
		sem <- 0
		scanHostWg.Add(1)
		if (i+1)%100 == 0 {
			fmt.Printf("Scanning host %d/%d\n", i+1, len(*hosts_p))
		}
		go func(host string, ports_p *portlist, printerCh chan<- ScanResult) {
			scanHost(host, ports_p, printerCh, false)
			<-sem
		}(host, ports_p, printerCh)
	}

	// Wait for all running scans to finish and send printer a signal to stop.
	scanHostWg.Wait()
	printerCh <- ScanResult{}
	// Wait for the printer to announce all results.
	printerWg.Wait()
}

func vulnScanHostPorts(host string, ports_p *portlist) {

}

// Printer prints the results from scanHost.
func printer(ch <-chan ScanResult) {
	defer printerWg.Done()

	// Based on https://github.com/mattn/go-sqlite3/blob/master/_example/simple/simple.go.
	// Open a sqlite3 database.
	db, err := sql.Open("sqlite3", SQLITE3_DATABASE_PATH)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Create a table to store scan results if it does not exist.
	stmt, err := db.Prepare(CREATE_TABLE_QUERY)
	if err != nil {
		log.Fatal(err)
	}
	_, err = stmt.Exec()
	if err != nil {
		log.Fatalf("%q: %s\n", err, stmt)
	}

	// Insert each scan result into the database.
	tx, err := db.Begin()
	if err != nil {
		log.Fatal(err)
	}
	stmt, err = tx.Prepare(INSERT_TABLE_QUERY)
	if err != nil {
		log.Fatal(err)
	}
	defer stmt.Close()

	for scanResult := <-ch; scanResult != (ScanResult{}); scanResult = <-ch {
		_, err = stmt.Exec(scanResult.hostIP, scanResult.portNumber, scanResult.timestamp, scanResult.open, scanResult.nmapOutput)
		if err != nil {
			log.Fatal(err)
		}
		log.Print(scanResult)
	}
	tx.Commit()
}

func main() {
	rand.Seed(time.Now().UnixNano())

	///////////////////////////////////
	// Parse command-line arguments. //
	///////////////////////////////////
	// Set usage message for -h flag.
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "USAGE: %s -hosts HOSTS -ports PORTS HOSTS\n", os.Args[0])
		flag.PrintDefaults()
	}
	// The program shall be invoked by
	//   go run iceland_scanner.go -h HOSTS -p PORTS
	// or
	//   go run iceland_scanner.go -known-open -p PORTS
	// or
	//   go run iceland_scanner.go -vuln-scan
	// where PORTS is a comma separated list of port ranges separated by -,
	// and HOSTS is a space separated list of hosts.
	var hosts hostlist
	var ports portlist
	var vulnScanList = make(map[string]portlist)
	var knownOpen bool
	var vulnScan bool
	flag.Var(&hosts, "hosts", "a comma-separated list of host ranges to scan")
	flag.Var(&ports, "ports", "a comma-separated list of port ranges to scan")
	flag.BoolVar(&knownOpen, "known-open", false, "only scan hosts with known open ports (taken from database)")
	flag.BoolVar(&vulnScan, "vuln-scan", false, "perform vuln scan on known open hosts")
	flag.Parse()

	// Make sure we got hosts and ports, or known-open flag and ports.
	if !(len(hosts) > 0 && len(ports) > 0) && !(knownOpen && len(ports) > 0) && !vulnScan {
		log.Printf("must provide either hosts and ports, or known-open flag and ports, or vuln-scan flag\n\n")
		flag.Usage()
		os.Exit(1)
	}

	// Can not have both -known-open and -vuln-scan flags at the same time.
	if knownOpen && vulnScan {
		log.Printf("can not have both known-open and vuln-scan flags at the same time\n\n")
		flag.Usage()
		os.Exit(1)
	}

	// If hosts are provided with the known-open flag then they will be ignored.
	// The known-open flag grabs known open hosts from database.
	if len(hosts) > 0 && knownOpen {
		log.Print("hosts are ignored during known-open scan")
		log.Printf("known-open scan scans ports on known open hosts from %q\n\n", SQLITE3_DATABASE_PATH)
	}

	// If we are performing a known-open scan then we only scan known open
	// hosts. Open the database and grab every host that had an open port.
	if knownOpen {
		// Clear hosts array.
		hosts = make(hostlist, 0)
		// Based on https://github.com/mattn/go-sqlite3/blob/master/_example/simple/simple.go.
		// Open a sqlite3 database.
		db, err := sql.Open("sqlite3", SQLITE3_DATABASE_PATH)
		if err != nil {
			log.Fatal(err)
		}
		defer db.Close()

		// Grab hosts with known open ports from database.
		rows, err := db.Query("SELECT DISTINCT host_ip FROM scan_results WHERE open=1")
		if err != nil {
			log.Println(err)
			if strings.Contains(err.Error(), "no such table") {
				log.Println("did you discover hosts first (without -known-open)?")
			}
			os.Exit(1)
		}
		// Loop over results and store hosts in hostlist.
		defer rows.Close()
		for rows.Next() {
			var host string
			err = rows.Scan(&host)
			if err != nil {
				log.Fatal(err)
			}
			hosts = append(hosts, host)
		}
	}

	// If we are performing a vuln-scan scan then we only scan known open
	// host:port combinations. Open the database and grab every open host:port
	// combination.
	if vulnScan {
		// Based on https://github.com/mattn/go-sqlite3/blob/master/_example/simple/simple.go.
		// Open a sqlite3 database.
		db, err := sql.Open("sqlite3", SQLITE3_DATABASE_PATH)
		if err != nil {
			log.Fatal(err)
		}
		defer db.Close()

		// Grab hosts with known open ports from database.
		rows, err := db.Query("SELECT DISTINCT host_ip FROM scan_results WHERE open=1")
		if err != nil {
			log.Println(err)
			if strings.Contains(err.Error(), "no such table") {
				log.Println("did you discover hosts first (without -vuln-scan)?")
			}
			os.Exit(1)
		}
		// Loop over results and store hosts.
		defer rows.Close()
		for rows.Next() {
			var host string
			err = rows.Scan(&host)
			if err != nil {
				log.Fatal(err)
			}
			vulnScanList[host] = make(portlist, 0)
		}

		// Grab known open ports for each host.
		for host := range vulnScanList {
			rows, err = db.Query("SELECT DISTINCT port_number FROM scan_results WHERE open=1 AND host_ip=?", host)
			if err != nil {
				log.Println(err)
				os.Exit(1)
			}
			// Loop over results and store hosts.
			defer rows.Close()
			for rows.Next() {
				var port int
				err = rows.Scan(&port)
				if err != nil {
					log.Fatal(err)
				}
				vulnScanList[host] = append(vulnScanList[host], port)
			}
		}
		for host, port := range vulnScanList {
			fmt.Printf("%s:%d\n", host, port)
		}
	}

	//////////////////////////////////////////
	// Scan every combination of host:port. //
	//////////////////////////////////////////
	// We create a string channel so that printer can do all the printing. This
	// ensures that the output from each goroutine is processed as a unit, and
	// prevents any unexpected outout if two goroutines finish at the same time.
	printerCh := make(chan ScanResult)
	printerWg.Add(1)
	go printer(printerCh)

	if !vulnScan {
		// Shuffle hosts to avoid IDS that monitor multiple hosts.
		rand.Shuffle(len(hosts), func(i int, j int) {
			hosts[i], hosts[j] = hosts[j], hosts[i]
		})
		// Shuffle ports to avoid IDS that monitors requests to sequential port
		// numbers.
		rand.Shuffle(len(ports), func(i int, j int) {
			ports[i], ports[j] = ports[j], ports[i]
		})
	}

	// Use a semaphore (limited capacity channel) to control the number of hosts
	// scanned concurrently.
	sem := make(chan interface{}, MAX_CONCURRENT_SCANS)
	// Loop over hosts and ports depending on vuln-scan or not.
	if vulnScan {
		i := 0
		// If vuln-scan then only scan known open ports for each host.
		for host, hostportlist := range vulnScanList {
			sem <- 0
			scanHostWg.Add(1)
			if (i+1)%1 == 0 {
				fmt.Printf("Scanning host %d/%d\n", i+1, len(vulnScanList))
			}
			i++
			go func(host string, ports_p *portlist, printerCh chan<- ScanResult) {
				scanHost(host, ports_p, printerCh, true)
				<-sem
			}(host, &hostportlist, printerCh)
		}
	} else {
		// If not vuln-scan then scan all ports on every host.
		for i, host := range hosts {
			sem <- 0
			scanHostWg.Add(1)
			if (i+1)%100 == 0 {
				fmt.Printf("Scanning host %d/%d\n", i+1, len(hosts))
			}
			go func(host string, ports_p *portlist, printerCh chan<- ScanResult) {
				scanHost(host, ports_p, printerCh, false)
				<-sem
			}(host, &ports, printerCh)
		}
	}

	// Wait for all running scans to finish and send printer a signal to stop.
	scanHostWg.Wait()
	printerCh <- ScanResult{}
	// Wait for the printer to announce all results.
	printerWg.Wait()
}
