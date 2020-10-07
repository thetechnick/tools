# Copyright 2020 thetechnick.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# -------
# Compile
# -------
all: \
	all-mipsle \
	all-mips \
	all-mips64

all-mipsle: \
	bin/linux_mipsle/dhcpv6-pd-refreshd

all-mips: \
	bin/linux_mips/dhcpv6-pd-refreshd

all-mips64: \
	bin/linux_mips64/dhcpv6-pd-refreshd

bin/linux_amd64/%: GOARGS = GOOS=linux GOARCH=amd64
bin/linux_mipsle/%: GOARGS = GOOS=linux GOARCH=mipsle
bin/linux_mips/%: GOARGS = GOOS=linux GOARCH=mips
bin/linux_mips64/%: GOARGS = GOOS=linux GOARCH=mips64

bin/%: FORCE
	$(eval COMPONENT=$(shell basename $*))
	$(GOARGS) go build -o bin/$* cmd/$(COMPONENT)/main.go

FORCE:

clean:
	@rm -rf bin
