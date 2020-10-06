# -------
# Compile
# -------
all: \
	all-mipsle \
	all-mips \
	all-mips64

all-mipsle: \
	bin/linux_mipsle/dhcpv6-ipset \
	bin/linux_mipsle/dhcpv6-pd-refreshd

all-mips: \
	bin/linux_mips/dhcpv6-ipset \
	bin/linux_mips/dhcpv6-pd-refreshd

all-mips64: \
	bin/linux_mips64/dhcpv6-ipset \
	bin/linux_mips64/dhcpv6-pd-refreshd

bin/linux_amd64/%: GOARGS = GOOS=linux GOARCH=amd64
bin/linux_mipsle/%: GOARGS = GOOS=linux GOARCH=mipsle
bin/linux_mips/%: GOARGS = GOOS=linux GOARCH=mips
bin/linux_mips64/%: GOARGS = GOOS=linux GOARCH=mips64

bin/%: FORCE
	$(eval COMPONENT=$(shell basename $*))
	$(GOARGS) go build -o bin/$* cmd/$(COMPONENT)/main.go

FORCE:
