package main

import (
	"encoding/hex"
	"github.com/jdelic/opensmtpd-filters-go"
	"net"
	"strings"
)


type DNSBLFilter struct {

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
	return "unimplemented"
}


func ipToQueryPrefix(ipstr string) string {
	ip := net.ParseIP(ipstr)
	if ip.To16() != nil {
		return prepareIpv6(expandIpv6(ip))
	} else {
		return prepareIpv4(ip.String())
	}
}


/* <unknown>|fail|192.168.56.162:53878|192.168.56.162:25 */
func (d *DNSBLFilter) LinkConnect(session string, params []string) {
	srcip := params[2]
	if srcip[0:4] == "unix" {
		// unix socket
	} else {
		//query := ipToQueryPrefix(srcip)
	}
}

func main() {

}
