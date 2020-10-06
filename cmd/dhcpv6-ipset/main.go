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
	"time"

	// "github.com/romana/ipset"
	"github.com/thetechnick/go-ipset"
	"github.com/thetechnick/tools/internal/ipv6"
)

func main() {
	// Run
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()

	if err := run(); err != nil {
		fmt.Printf("Error: %v\n", err)
	}
	for range t.C {
		if err := run(); err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	}
}

func run() error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("listing interfaces: %w", err)
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return fmt.Errorf("listing interface %q addresses: %w", iface.Name, err)
		}

		ipset, err := ipset.New()
		if err != nil {
			return fmt.Errorf("connecting to ipset: %w", err)
		}

		netSetName := "NETv6_" + iface.Name
		if err := ipset.Create(netSetName, "hash:net", "-exist", "family", "inet6"); err != nil {
			return fmt.Errorf("creating new ipset set %s: %w", netSetName, err)
		}

		addrSetName := "ADDRv6_" + iface.Name
		if err := ipset.Create(addrSetName, "hash:net", "-exist", "family", "inet6"); err != nil {
			return fmt.Errorf("creating new ipset set %s: %w", addrSetName, err)
		}

		var (
			ipv6Nets  = map[string]struct{}{}
			ipv6Addrs = map[string]struct{}{}
		)
		for _, addr := range addrs {
			ip, net, err := net.ParseCIDR(addr.String())
			if err != nil {
				return fmt.Errorf("%w", err)
			}

			if ip.To4() != nil {
				continue
			}
			if ipv6.IsLinkLocal(ip) {
				continue
			}

			ipv6Nets[net.String()] = struct{}{}
			if err := ipset.AddUnique(netSetName, net.String()); err != nil {
				return fmt.Errorf("adding member %q to set %s: %w", net.String(), netSetName, err)
			}
			ipv6Addrs[ip.String()] = struct{}{}
			if err := ipset.AddUnique(addrSetName, ip.String()); err != nil {
				return fmt.Errorf("adding member %q to set %s: %w", ip.String(), netSetName, err)
			}
		}

		// Cleanup outdated ip addresses
		nets, err := ipset.List(netSetName)
		if err != nil {
			return fmt.Errorf("listing members of set %s: %w", netSetName, err)
		}
		for _, net := range nets {
			if _, ok := ipv6Nets[net]; !ok {
				// delete
				if err := ipset.Delete(netSetName, net); err != nil {
					return fmt.Errorf("deleting member of set %s: %w", netSetName, err)
				}
			}
		}

		nets, err = ipset.List(addrSetName)
		if err != nil {
			return fmt.Errorf("listing members of set %s: %w", addrSetName, err)
		}
		for _, net := range nets {
			if _, ok := ipv6Addrs[net]; !ok {
				// delete
				if err := ipset.Delete(addrSetName, net); err != nil {
					return fmt.Errorf("deleting member of set %s: %w", addrSetName, err)
				}
			}
		}
	}
	return nil
}
