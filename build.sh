#!/bin/bash
go get
go build

fpm \
    -s dir \
    -t deb \
    -p opensmtpd-filter-dnsbl_0.1.1.deb \
    -n opensmtpd-filter-dnsbl \
    -v "0.1.1-0" \
    -m "Jonas Maurus" \
    -d "opensmtpd (>=6.6.0)" \
    -d "opensmtpd (<<6.7)" \
    --description "Provides integration with DNS blacklists for OpenSMTPD." \
    --url "https://github.com/jdelic/opensmtpd-filter-dnsbl" \
    opensmtpd-filter-dnsbl=/usr/lib/x86_64-linux-gnu/opensmtpd/filter-dnsbl
