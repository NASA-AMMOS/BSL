# BSL Mock BPA Test
This directory contains a set of pytest-compatible test fixtures to exercise the Mock BPA.
It will run using `./build.sh run` which will execute with a PATH environment preferring `./testroot/usr/bin` followed by system paths.
This means it can test a local build as well as test the installed RPM packages.

Tests can be logged using Wireshark similar to
```sh
wireshark -i lo -k \
    -f 'udp port 4556 or udp port 14556 or udp port 24556 or udp port 34556' \
    -d 'udp.port==14556,bundle' -d 'udp.port==24556,bundle' -d 'udp.port==34556,bundle' \
    -Y bpv7
```