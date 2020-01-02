Golang implementation of a RBL DNS blacklist filter for OpenSMTPD
=================================================================

This is a simple implementation based off my
`opensmtpd-filters-go <osfgo_>`__ library.


Example usage in smtpd.conf
---------------------------

::

    filter "dnsbl" proc-exec "/usr/lib/x86_64-linux-gnu/opensmtpd/filter-dnsbl ix.dnsbl.manitu.net"
    listen on "127.0.0.1" port 25 filter dnsbl


.. _osfgo: https://github.com/jdelic/opensmtpd-filters-go
