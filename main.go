package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/jdelic/opensmtpd-filters-go"
	"log"
	"net"
	"os"
	"strings"
)


type DNSBLFilter struct {}

func (d *DNSBLFilter) GetName() string {
	return "DNS blacklist filter"
}

func debug(format string, values... interface{}) {
	if *debugOutput {
		log.Printf(format, values...)
	}
}


func expandIpv6(input net.IP) string {
	dst := make([]byte, hex.EncodedLen(len(input)))
	_ = hex.Encode(dst, input)
	return string(dst[0:4]) + ":" +
		string(dst[4:8]) + ":" +
		string(dst[8:12]) + ":" +
		string(dst[12:16]) + ":" +
		string(dst[16:20]) + ":" +
		string(dst[20:24]) + ":" +
		string(dst[24:28]) + ":" +
		string(dst[28:])
}


func prepareIpv6(address string) string {
	address = strings.Join(strings.Split(address, ":"), "")

	ret := ""
	for i := len(address) - 1; i >= 0; i = i - 1 {
		if i < len(address) - 1 {
			ret = ret + "."
		}
		ret = ret + address[i:i+1]
	}

	return ret
}


func prepareIpv4(address string) string {
	reversed := strings.Split(address, ".")

	for i, j := 0, 3; i < 2; i, j = i + 1, j - 1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}

	return strings.Join(reversed, ".")
}


func ipToQueryPrefix(ipstr string) (string, error) {
	ip := net.ParseIP(ipstr)
	if ip.To4() != nil {
		return prepareIpv4(ip.String()), nil
	} else if ip.To16() != nil {
		return prepareIpv6(expandIpv6(ip)), nil
	} else {
		return "", fmt.Errorf("invalid IP: %v", ipstr)
	}
}


/* <unknown>|fail|192.168.56.162:53878|192.168.56.162:25 */
func (d *DNSBLFilter) Connect(fw opensmtpd.FilterWrapper, ev opensmtpd.FilterEvent) {
	conn := ev.GetParams()[2]
	if conn[0:4] == "unix" {
		debug("Unix socket.")
		return
	} else {
		queryPart, err := ipToQueryPrefix(strings.Trim(conn, "[]"))
		if err != nil {
			debug("Debug: Error during IP processing %v\n", err)
			ev.Responder().SoftReject("Failure in IP processing")
			return
		}

		// make a channel with enough buffer to receive all results, so we don't leak
		// goroutines when we bail before having received all DNS results
		repliesChan := make(chan string, len(flag.Args()))

		go func(replyChan chan string) {
			for _, host := range flag.Args() {
				query := fmt.Sprintf("%v.%v", queryPart, host)

				go func(host string) {
					debug("Debug: Querying %v\n", query)
					_, err := net.LookupHost(query)
					if err == nil {
						replyChan <- host
					} else {
						debug("DNS Response from %v: %v", host, err)
						replyChan <- ""
					}
				}(host)
			}

			for i := 0; i < len(flag.Args()); i++ {
				reply := <- replyChan

				if reply != "" {
					ev.Responder().HardReject(
						fmt.Sprintf("Your host is listed on blacklist %v", reply))
					return  // bail after we received one positive answer
				}
			}

			// if we have received all replies and none were true, we proceed
			ev.Responder().Proceed()
		}(repliesChan)
	}
}


func Usage() {
	fmt.Printf("Usage: %s [OPTIONS] dnsbl host 1 [dnsbl host2...]", os.Args[0])
	flag.PrintDefaults()
	os.Exit(1)
}


var debugOutput *bool


func main() {
	log.SetOutput(os.Stderr)
	debugOutput = flag.Bool("debug", false, "Enable debug output")
	flag.Usage = Usage
	flag.Parse()
	if flag.NArg() < 1 {
		flag.Usage()
	}

	dnsblFilter := opensmtpd.NewFilter(&DNSBLFilter{})
	opensmtpd.Run(dnsblFilter)
}
