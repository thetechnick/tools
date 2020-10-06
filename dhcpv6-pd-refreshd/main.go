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
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"time"
)

var (
	LinkLocalNet   *net.IPNet
	PrefixMask     net.IPMask
	CheckInterface string
)

const (
	REFRESHED_CHECK_INTERFACE = "REFRESHED_CHECK_INTERFACE"
	REFRESHED_PREFIX_LEN      = "REFRESHED_PREFIX_LEN"
)

func main() {
	// Env
	CheckInterface = os.Getenv(REFRESHED_CHECK_INTERFACE)
	prefixLength := os.Getenv(REFRESHED_PREFIX_LEN)

	if CheckInterface == "" {
		fmt.Printf("env %q: is required\n", REFRESHED_CHECK_INTERFACE)
		os.Exit(1)
	}
	if prefixLength == "" {
		fmt.Printf("env %q: is required\n", prefixLength)
		os.Exit(1)
	}

	// Setup
	var err error
	_, LinkLocalNet, err = net.ParseCIDR("fe80::/10")
	if err != nil {
		panic(err)
	}

	_, prefixNet, err := net.ParseCIDR("fe80::" + prefixLength)
	if err != nil {
		panic(err)
	}
	PrefixMask = prefixNet.Mask

	scriptPath, err := ensureScript()
	if err != nil {
		fmt.Printf("creating script file: %v\n", err)
		os.Exit(1)
	}

	// Run
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()

	if err := run(scriptPath); err != nil {
		fmt.Printf("Error: %v\n", err)
	}
	for range t.C {
		if err := run(scriptPath); err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	}
}

func run(scriptPath string) error {
	ip, err := getInterfaceIPv6(CheckInterface)
	if err != nil {
		return fmt.Errorf("getting ipv6 for interface %q: %w", CheckInterface, err)
	}
	if ip == nil {
		fmt.Printf("no matching ip on %q\n", CheckInterface)
		return nil
	}

	delegatedPrefix := &net.IPNet{
		IP:   ip.Mask(PrefixMask),
		Mask: PrefixMask,
	}

	includes, err := hostDNSIncludes("fritz.box", delegatedPrefix)
	if err != nil {
		return fmt.Errorf("lookup fritz.box ip: %w", err)
	}
	if includes {
		fmt.Printf("delegated prefix %q of interface %q found on fritzbox!\n", delegatedPrefix.String(), CheckInterface)
		return nil
	}

	fmt.Printf("delegated prefix %q of interface %q NOT found on fritzbox! REFRESH NEEDED\n", delegatedPrefix.String(), CheckInterface)

	// we have to refresh the prefix
	cmd := exec.Command(scriptPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("refreshing dhcpv6-pd: %w: %s", err, out)
	}
	return nil
}

const renewDHCPv6PDScript = `#!/bin/vbash

/opt/vyatta/bin/vyatta-op-cmd-wrapper release dhcpv6-pd interface eth0
/opt/vyatta/bin/vyatta-op-cmd-wrapper delete dhcpv6-pd duid
/opt/vyatta/bin/vyatta-op-cmd-wrapper renew dhcpv6-pd interface eth0
`

func ensureScript() (string, error) {
	script, err := ioutil.TempFile("", "")
	if err != nil {
		return "", fmt.Errorf("creating dhcpv6-pd renew script: %w", err)
	}
	defer script.Close()
	if err := script.Chmod(0744); err != nil {
		return "", fmt.Errorf("chmod review script: %w", err)
	}
	_, err = script.Write([]byte(renewDHCPv6PDScript))
	if err != nil {
		return "", fmt.Errorf("cant write dhcpv6-pd renew script: %w", err)
	}
	return script.Name(), nil
}

func hostDNSIncludes(host string, delegatedPrefix *net.IPNet) (bool, error) {
	lookupIPs, err := net.LookupHost(host)
	if err != nil {
		return false, fmt.Errorf("lookup fritz.box: %w", err)
	}
	fmt.Printf("found %v addresses on %q\n", lookupIPs, host)
	for _, lookupIP := range lookupIPs {
		if delegatedPrefix.Contains(net.ParseIP(lookupIP)) {
			return true, nil
		}
	}
	return false, nil
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
	fmt.Printf("found ips: %v\n", addrs)

	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil {
			return nil, fmt.Errorf("parsing CIDR %q: %w", addr.String(), err)
		}
		if ip.To4() != nil {
			continue
		}
		if LinkLocalNet.Contains(ip) {
			continue
		}
		return ip, nil
	}
	return nil, nil
}
