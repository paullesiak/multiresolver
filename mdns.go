package multiresolver

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/pion/mdns/v2"
	"golang.org/x/net/ipv4"
)

// MDNSQuery resolves a host via mDNS and returns a single address.
type MDNSQuery func(ctx context.Context, host string) (netip.Addr, error)

// MDNS creates a candidate that performs multicast DNS lookups using the default implementation.
func MDNS(name string) Candidate {
	return MDNSWithQuery(name, nil)
}

// MDNSWithQuery creates an mDNS candidate that uses the provided query function. Supplying nil falls back to
// the default mDNS stack that ships with this package.
func MDNSWithQuery(name string, query MDNSQuery) Candidate {
	if query == nil {
		query = defaultMDNSQuery
	}
	return Candidate{
		Name: name,
		Lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			addr, err := query(ctx, host)
			if err != nil {
				return nil, err
			}
			if !addr.IsValid() {
				return nil, errors.New("invalid mDNS address")
			}
			return []netip.Addr{addr}, nil
		},
	}
}

func defaultMDNSQuery(ctx context.Context, host string) (netip.Addr, error) {
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return netip.Addr{}, err
	}
	defer conn.Close()

	packetConn := ipv4.NewPacketConn(conn)
	packetConn.SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true)

	server, err := mdns.Server(packetConn, nil, &mdns.Config{})
	if err != nil {
		return netip.Addr{}, err
	}
	defer server.Close()

	_, addr, err := server.QueryAddr(ctx, host)
	if err != nil {
		return netip.Addr{}, err
	}
	return addr, nil
}
