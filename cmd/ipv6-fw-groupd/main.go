/*
Copyright 2020 thetechnick.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bombsimon/logrusr"
	"github.com/go-logr/logr"
	"github.com/sirupsen/logrus"
	"github.com/thetechnick/go-ipset"
	"github.com/thetechnick/tools/internal/ipv6"
)

const (
	IPV6_FW_GROUPD                = "IPV6_FW_GROUPD"
	IPV6_FW_GROUPD_CHECK_DURATION = IPV6_FW_GROUPD + "_CHECK_DURATION"
)

func main() {
	log := logrusr.NewLogger(logrus.New())

	// Env
	checkDurationEnv := os.Getenv(IPV6_FW_GROUPD_CHECK_DURATION)
	if checkDurationEnv == "" {
		checkDurationEnv = "5s"
	}
	checkDuration, err := time.ParseDuration(checkDurationEnv)
	if err != nil {
		log.Error(err, "cannot parse env "+IPV6_FW_GROUPD_CHECK_DURATION)
		os.Exit(1)
	}

	// Run
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	daemon, err := NewDaemon(log, checkDuration)
	if err != nil {
		log.Error(err, "creating daemon")
		os.Exit(1)
	}

	stopCh := make(chan struct{})
	defer close(stopCh)
	daemon.Start(stopCh)

	<-sigs
}

// This daemon puts non-link-local ipv6 addresses and
// their network into ipset-sets to serve as target for firewall rules.
//
// Example Sets: ADDRv6_eth0, NETv6_eth0
//
// It mimics the available IPv4 sets already available on the Ubiquity EdgeRouter.
type Daemon struct {
	log           logr.Logger
	ipset         *ipset.IPSet
	checkDuration time.Duration
}

func NewDaemon(log logr.Logger, checkDuration time.Duration) (*Daemon, error) {
	ips, err := ipset.New()
	if err != nil {
		return nil, err
	}

	return &Daemon{
		log:           log,
		ipset:         ips,
		checkDuration: checkDuration,
	}, nil
}

func (d *Daemon) Start(stopCh <-chan struct{}) {
	go d.run(stopCh)
}

func (d *Daemon) run(stopCh <-chan struct{}) {
	d.log.Info("starting...")
	t := time.NewTicker(d.checkDuration)
	defer t.Stop()

	if err := d.reconcile(); err != nil {
		d.log.Error(err, "reconcile")
	}

	for {
		select {
		case <-t.C:
			if err := d.reconcile(); err != nil {
				d.log.Error(err, "reconcile")
			}

		case <-stopCh:
			return
		}
	}
}

func (d *Daemon) reconcile() error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("listing interfaces: %w", err)
	}

	for _, iface := range ifaces {
		if err := d.reconcileInterface(iface); err != nil {
			return fmt.Errorf("reconciling interface %q: %w", iface.Name, err)
		}
	}

	return nil
}

func (d *Daemon) reconcileInterface(iface net.Interface) error {
	// Create sets
	netSetName := "NETv6_" + iface.Name
	if err := d.ipset.Create(netSetName, "hash:net", "-exist", "family", "inet6"); err != nil {
		return fmt.Errorf("creating new ipset set %s: %w", netSetName, err)
	}
	addrSetName := "ADDRv6_" + iface.Name
	if err := d.ipset.Create(addrSetName, "hash:net", "-exist", "family", "inet6"); err != nil {
		return fmt.Errorf("creating new ipset set %s: %w", addrSetName, err)
	}

	// Add members into sets
	addrs, err := iface.Addrs()
	if err != nil {
		return fmt.Errorf("listing addresses: %w", err)
	}

	var (
		ipv6Nets  = map[string]struct{}{}
		ipv6Addrs = map[string]struct{}{}
	)
	for _, addr := range addrs {
		ip, net, err := net.ParseCIDR(addr.String())
		if err != nil {
			return fmt.Errorf("parsing CIDR: %w", err)
		}

		if !ipv6.IsIPv6(ip) {
			continue
		}
		if ipv6.IsLinkLocal(ip) {
			continue
		}

		ipv6Nets[net.String()] = struct{}{}
		if err := d.ipset.AddUnique(netSetName, net.String()); err != nil {
			return fmt.Errorf("adding member %q to set %s: %w", net.String(), netSetName, err)
		}

		ipv6Addrs[ip.String()] = struct{}{}
		if err := d.ipset.AddUnique(addrSetName, ip.String()); err != nil {
			return fmt.Errorf("adding member %q to set %s: %w", ip.String(), addrSetName, err)
		}
	}

	// Cleanup outdated members
	nets, err := d.ipset.List(netSetName)
	if err != nil {
		return fmt.Errorf("listing members of set %s: %w", netSetName, err)
	}
	for _, net := range nets {
		if _, ok := ipv6Nets[net]; ok {
			continue
		}

		if err := d.ipset.Delete(netSetName, net); err != nil {
			return fmt.Errorf("deleting member of set %s: %w", netSetName, err)
		}
	}

	nets, err = d.ipset.List(addrSetName)
	if err != nil {
		return fmt.Errorf("listing members of set %s: %w", addrSetName, err)
	}
	for _, net := range nets {
		if _, ok := ipv6Addrs[net]; ok {
			continue
		}

		if err := d.ipset.Delete(addrSetName, net); err != nil {
			return fmt.Errorf("deleting member of set %s: %w", addrSetName, err)
		}
	}

	d.log.Info(fmt.Sprintf(
		"reconciled ipsets %s (%d members) and %s (%d members)",
		addrSetName, len(ipv6Addrs), netSetName, len(ipv6Nets)))

	return nil
}
