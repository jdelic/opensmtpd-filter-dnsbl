package main

import (
	"testing"
)

func TestIpv6(t *testing.T) {
	if ip, err := ipToQueryPrefix("f000::1");
		ip != "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.f" || err != nil {
		t.Log(err)
		t.Fail()
	}
}

func TestIpv4(t *testing.T) {
	if ip, err := ipToQueryPrefix("192.168.0.1"); ip != "1.0.168.192" || err != nil {
		t.Log(err)
		t.Fail()
	}
}

func TestInvalidIp(t *testing.T) {
	if ip, err := ipToQueryPrefix("xyz"); ip != "" || err == nil {
		t.Fail()
	}
}
