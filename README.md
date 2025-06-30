<!--
Copyright (c) 2024 The Johns Hopkins University Applied Physics
Laboratory LLC.

This file is part of the Bundle Protocol Security Library (BSL).

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

This work was performed for the Jet Propulsion Laboratory, California
Institute of Technology, sponsored by the United States Government under
the prime contract 80NM0018D0004 between the Caltech and NASA under
subcontract 1700763.
-->
Building docker base images
```
docker image build . -f buildenv.Dockerfile --target buildenv-rtems-leon
```

Building and running locally:
```
# First time, or upon switching branches
git submodule update --init --recursive


./deps.sh
./prep.sh
./build.sh
./build.sh check
./build.sh coverage
./build.sh docs
./build.sh install
```

After running "coverage" target, the coverage report can be viewed with:
```
xdg-open build/default/coverage/index.html
```

After running "docs" target, the generated HTML can be viewed with:
```
xdg-open build/default/docs/doxygen/html/index.html
```

Note: On earlier versions of CMake (<3.20), `./build.sh check` target may not run correctly   
If ctest is not running, change `./build.sh`'s `check` target to:
```
elif [ "$1" = "check" ]
then
    pushd ${BUILDDIR}
    ctest \
	  --output-junit testresults.xml \
	  --verbose
    cmake --build ${BUILDDIR} --target coverage
fi
```

# API Documentation

Documentation of current API and detailed development conventions can be built and accessed directly from a working copy of BSL source tree.

The built documentation comes from a combination of the source itself under `./src` as well as separate markdown files under `./docs/*.md` and a BiBTeX reference list in `./docs/refs.bib`.

The first step is one-time instal of dependencies, which for Ubuntu 22.04 are:
```
sudo apt-get install -y doxygen graphviz
```
and then preparing the source project as for a software build using:
```
./deps.sh
./prep.sh
```
Once prepared, the documentation is built from the source using:
```
./build.sh docs
```
Finally, the built docs can be opened at the main page using:
```
xdg-open build/default/docs/doxygen/html/index.html
```

## Mock BPA Operation

```
wireshark -i lo -f 'port 4556 or port 24556' -k
```

Start the mock BPA with local sockets:
```
./build.sh
./run.sh bsl-mock-bpa -u localhost:4556 -r localhost:14556 -o localhost:24556 -a localhost:34556
```

Send a trial bundle from the underlayer, which is taken from Appendix A.1.4 of RFC 9173.
```
echo 9f88070000820282010282028202018202820201820018281a000f4240850b0200005856810101018202820201828201078203008181820158403bdc69b3a34a2b5d3a8554368bd1e808f606219d2a10a846eae3886ae4ecc83c4ee550fdfb1cc636b904e2f1a73e303dcd4b6ccece003e95e8164dcc89a156e185010100005823526561647920746f2067656e657261746520612033322d62797465207061796c6f6164ff | xxd -r -p | socat stdio udp-sendto:localhost:4556,pf=ip6,sourceport=14556 | xxd -p
```
Alternatively for the overlayer app socket use `socat stdio unix-sendto:/tmp/foo.sock` instead.
