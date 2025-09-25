package multiresolver

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/pion/mdns/v2"
	"golang.org/x/net/ipv4"
)

// MDNSQuery resolves a host via mDNS and returns a single address.
type MDNSQuery func(ctx context.Context, host string) (netip.Addr, error)

// MDNSOption customises the behaviour of the MDNS candidate constructor.
type MDNSOption func(*mdnsConfig)

type mdnsConfig struct {
	query MDNSQuery
}

// WithMDNSQuery replaces the underlying query implementation. It is primarily useful for tests or to
// substitute a platform-specific multicast DNS stack.
func WithMDNSQuery(query MDNSQuery) MDNSOption {
	return func(cfg *mdnsConfig) {
		cfg.query = query
	}
}

// MDNS returns a candidate that performs multicast DNS lookups using the provided options. When no
// overrides are supplied it falls back to defaultMDNSQuery which manages the socket lifecycle and
// listens for responses on the IPv4 mDNS multicast group.
func MDNS(name string, opts ...MDNSOption) Candidate {
	cfg := mdnsConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}
	query := cfg.query
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
	// Listening on a random UDP4 port keeps us from conflicting with the system daemon while still
	// allowing queries to be issued on-demand.
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return netip.Addr{}, err
	}
	defer conn.Close()

	packet := ipv4.NewPacketConn(conn)
	packet.SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true)

	server, err := mdns.Server(packet, nil, &mdns.Config{})
	if err != nil {
		return netip.Addr{}, err
	}
	defer server.Close()

	type result struct {
		addr netip.Addr
		err  error
	}

	done := make(chan result, 1)
	go func() {
		_, src, err := server.QueryAddr(ctx, host)
		done <- result{addr: src, err: err}
	}()

	select {
	case <-ctx.Done():
		return netip.Addr{}, ctx.Err()
	case res := <-done:
		return res.addr, res.err
	case <-time.After(5 * time.Second):
		return netip.Addr{}, context.DeadlineExceeded
	}
}
