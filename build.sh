#!/bin/bash
go get
go build

fpm \
    -s dir \
    -t deb \
    -p opensmtpd-filter-dnsbl_0.1.3.deb \
    -n opensmtpd-filter-dnsbl \
    -v "0.1.3-0" \
    -m "Jonas Maurus" \
    -d "opensmtpd (>=6.8.0)" \
    -d "opensmtpd (<<7.5)" \
    --description "Provides integration with DNS blacklists for OpenSMTPD." \
    --url "https://github.com/jdelic/opensmtpd-filter-dnsbl" \
    opensmtpd-filter-dnsbl=/usr/lib/x86_64-linux-gnu/opensmtpd/filter-dnsbl
