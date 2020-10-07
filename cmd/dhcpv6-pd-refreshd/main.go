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
	"html/template"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/bombsimon/logrusr"
	"github.com/go-logr/logr"
	"github.com/sirupsen/logrus"
	"github.com/thetechnick/tools/internal/ipv6"
)

const (
	REFRESHD                 = "REFRESHD"
	REFRESHD_PREFIX_LEN      = REFRESHD + "_PREFIX_LEN"
	REFRESHD_CHECK_INTERFACE = REFRESHD + "_CHECK_INTERFACE"
	REFRESHD_CHECK_DURATION  = REFRESHD + "_CHECK_DURATION"
	REFRESHD_DNS_HOST        = REFRESHD + "_DNS_HOST"
	REFRESHD_FORCE           = REFRESHD + "_FORCE"
)

func main() {
	log := logrusr.NewLogger(logrus.New())

	// Env
	checkInterfaceEnv := os.Getenv(REFRESHD_CHECK_INTERFACE)
	prefixLengthEnv := os.Getenv(REFRESHD_PREFIX_LEN)
	checkDurationEnv := os.Getenv(REFRESHD_CHECK_DURATION)
	dnsHost := os.Getenv(REFRESHD_DNS_HOST)

	if checkInterfaceEnv == "" && os.Getenv(REFRESHD_FORCE) != "" {
		fmt.Printf("env %q: is required\n", REFRESHD_CHECK_INTERFACE)
		os.Exit(1)
	}

	if prefixLengthEnv == "" {
		prefixLengthEnv = "56"
	}
	n, err := strconv.Atoi(prefixLengthEnv)
	if err != nil {
		fmt.Printf("env %q: must be an integer\n", REFRESHD_PREFIX_LEN)
		os.Exit(1)
	}
	prefixMask := net.CIDRMask(n, 8*net.IPv6len)

	if checkDurationEnv == "" {
		checkDurationEnv = "5s"
	}
	checkDuration, err := time.ParseDuration(checkDurationEnv)
	if err != nil {
		log.Error(err, "cannot parse env "+REFRESHD_CHECK_DURATION)
		os.Exit(1)
	}

	if dnsHost == "" {
		dnsHost = "fritz.box"
	}

	// Setup
	renewScript, err := ensureRenewScript()
	if err != nil {
		log.Error(err, "ensuring script file")
		os.Exit(1)
	}

	// Run
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	daemon, err := NewDaemon(
		log, checkDuration, prefixMask, checkInterfaceEnv, dnsHost, renewScript)
	if err != nil {
		log.Error(err, "creating daemon")
		os.Exit(1)
	}

	if os.Getenv(REFRESHD_FORCE) != "" {
		log.Info("executing FORCE renew!")
		if err := daemon.renew(); err != nil {
			log.Error(err, "executing renew")
			os.Exit(1)
		}
		os.Exit(0)
	}

	stopCh := make(chan struct{})
	defer close(stopCh)
	daemon.Start(stopCh)

	<-sigs
}

// This daemon checks the DNS AAAA records of a host and when the host AAAA
// does not contain the ISP delegated IPv6 Prefix anymore,
// it will trigger a renew of the DHCPv6 PD lease to refresh the delegated prefix.
//
// In my network the host is a fritzbox and my edgerouter gets a prefix delegated.
// Due to long (2h) lifetime of the prefix delegation,  it takes about 1h to refresh the DHCPv6 lease and leads to a 1h downtime of IPv6 networking.
// Clients behind the edgerouter are configured via SLAAC and get the new prefix pushed via router advertisement.
type Daemon struct {
	log                                 logr.Logger
	checkDuration                       time.Duration
	prefixMask                          net.IPMask
	interfaceName, dnsHost, renewScript string
	firewallRenewScriptTemplate         *template.Template
}

func NewDaemon(
	log logr.Logger,
	checkDuration time.Duration,
	prefixMask net.IPMask,
	interfaceName, dnsHost, renewScript string,
) (*Daemon, error) {
	t, err := template.New("interface-script").Parse(scriptTemplate)
	if err != nil {
		return nil, err
	}

	return &Daemon{
		log:                         log,
		checkDuration:               checkDuration,
		prefixMask:                  prefixMask,
		interfaceName:               interfaceName,
		dnsHost:                     dnsHost,
		renewScript:                 renewScript,
		firewallRenewScriptTemplate: t,
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

	if err := d.renewFirewallGroups(); err != nil {
		d.log.Info("renew firewall groups: %w", err)
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
	ip, err := getInterfaceIPv6(d.interfaceName)
	if err != nil {
		return fmt.Errorf("getting ipv6 for interface %q: %w", d.interfaceName, err)
	}

	if ip == nil {
		d.log.Info(
			"no non-link-local ipv6 on interface", "interface", d.interfaceName)
		return nil
	}

	// ISP delegated prefix
	delegatedPrefix := &net.IPNet{
		IP:   ip.Mask(d.prefixMask),
		Mask: d.prefixMask,
	}

	// Check DNS
	lookupIPs, err := net.LookupHost(d.dnsHost)
	if err != nil {
		return fmt.Errorf("lookup %s: %w", d.dnsHost, err)
	}
	if anyIPContainedInNetwork(lookupIPs, delegatedPrefix) {
		d.log.Info(
			"hosts AAAA record contained in active prefix",
			"host", d.dnsHost, "prefix", delegatedPrefix.String())
		return nil
	}

	// Renew Prefix Delegation lease
	d.log.Info(
		"renewing DHCPv6-PD lease, old prefix is outdated",
		"old_prefix", delegatedPrefix.String())
	if err := d.renew(); err != nil {
		return err
	}
	return nil
}

func (d *Daemon) renew() error {
	cmd := exec.Command(d.renewScript)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("renew dhcpv6-pd: %w: %s", err, out)
	}

	// Renew Firewall Groups
	if err := d.renewFirewallGroups(); err != nil {
		return fmt.Errorf("renew firewall groups: %w", err)
	}
	return nil
}

// checks whether any of the given ips is contained in the given network.
func anyIPContainedInNetwork(ips []string, network *net.IPNet) bool {
	for _, ip := range ips {
		if network.Contains(net.ParseIP(ip)) {
			return true
		}
	}
	return false
}

const renewDHCPv6PDScript = `#!/bin/vbash

/opt/vyatta/bin/vyatta-op-cmd-wrapper release dhcpv6-pd interface eth0
/opt/vyatta/bin/vyatta-op-cmd-wrapper delete dhcpv6-pd duid
/opt/vyatta/bin/vyatta-op-cmd-wrapper renew dhcpv6-pd interface eth0
`

func ensureRenewScript() (string, error) {
	script, err := ioutil.TempFile("", "")
	if err != nil {
		return "", fmt.Errorf("creating dhcpv6-pd renew script: %w", err)
	}
	defer script.Close()
	if err := script.Chmod(0744); err != nil {
		return "", fmt.Errorf("chmod renew script: %w", err)
	}
	_, err = script.Write([]byte(renewDHCPv6PDScript))
	if err != nil {
		return "", fmt.Errorf("cant write dhcpv6-pd renew script: %w", err)
	}
	return script.Name(), nil
}

func getInterfaceIPv6(name string) (net.IP, error) {
	inf, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("getting interface: %w", err)
	}

	addrs, err := inf.Addrs()
	if err != nil {
		return nil, fmt.Errorf("getting addresses on interface: %w", err)
	}

	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil {
			return nil, fmt.Errorf("parsing CIDR %q: %w", addr.String(), err)
		}
		if !ipv6.IsIPv6(ip) {
			continue
		}
		if ipv6.IsLinkLocal(ip) {
			continue
		}
		return ip, nil
	}
	return nil, nil
}

const scriptTemplate = `#!/bin/vbash

/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper begin

{{range $interface := .Interfaces}}
{{$i := .Name}}
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper delete firewall group ipv6-address-group NETv6_{{$i}}
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper delete firewall group ipv6-address-group ADDRv6_{{$i}}

{{range $address := .Addresses}}
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper set firewall group ipv6-address-group ADDRv6_{{$i}} ipv6-address {{$address}}
{{end}}

{{range $network := .Networks}}
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper set firewall group ipv6-address-group NETv6_{{$i}} ipv6-address {{$network}}
{{end}}
{{end}}

/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper commit
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper save
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper end
`

type scriptContext struct {
	Interfaces []interfaceContext
}

type interfaceContext struct {
	Name      string
	Addresses []string
	Networks  []string
}

func (d *Daemon) renewFirewallGroups() error {
	// Build Context
	scriptCtx := &scriptContext{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("listing interfaces: %w", err)
	}

	for _, iface := range ifaces {
		ifaceCtx := interfaceContext{
			Name: iface.Name,
		}

		addrs, err := iface.Addrs()
		if err != nil {
			return fmt.Errorf("listing addresses: %w", err)
		}

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

			ifaceCtx.Addresses = append(ifaceCtx.Addresses, ip.String())
			ifaceCtx.Networks = append(ifaceCtx.Networks, net.String())
		}

		scriptCtx.Interfaces = append(scriptCtx.Interfaces, ifaceCtx)
	}

	// Execute Template and Script
	file, err := ioutil.TempFile("", "")
	if err != nil {
		return fmt.Errorf("opening temp file: %w", err)
	}
	defer file.Close()
	defer os.Remove(file.Name())
	if err := d.firewallRenewScriptTemplate.Execute(file, scriptCtx); err != nil {
		return fmt.Errorf("templating interface script: %w", err)
	}
	if err := file.Chmod(0744); err != nil {
		return fmt.Errorf("chmod renew script: %w", err)
	}
	file.Close()

	cmd := exec.Command(file.Name())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("refreshing interface ips: %w: %s", err, out)
	}

	return nil
}
