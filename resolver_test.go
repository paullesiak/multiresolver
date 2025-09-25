package multiresolver

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type testCase struct {
	name       string
	ctx        func() context.Context
	candidates []Candidate
	assert     func(t *testing.T, res Result, err error)
}

func TestResolverResolve(t *testing.T) {
	slow := newDelayedCandidate("slow", 30*time.Millisecond, []string{"10.0.0.2"}, nil)
	fast := newDelayedCandidate("fast", 5*time.Millisecond, []string{"10.0.0.1"}, nil)
	failing := newDelayedCandidate("failing", 10*time.Millisecond, nil, errors.New("boom"))
	cases := []testCase{
		{
			name: "returns first successful lookup",
			ctx: func() context.Context {
				ctx, _ := context.WithTimeout(context.Background(), time.Second)
				return ctx
			},
			candidates: []Candidate{slow, fast},
			assert: func(t *testing.T, res Result, err error) {
				require.NoError(t, err)
				require.Equal(t, "fast", res.Source)
				require.Equal(t, "example.com", res.Host)
				require.Len(t, res.Addrs, 1)
				require.Equal(t, netip.MustParseAddr("10.0.0.1"), res.Addrs[0])
			},
		},
		{
			name: "returns error when all lookups fail",
			ctx: func() context.Context {
				ctx, _ := context.WithTimeout(context.Background(), 100*time.Millisecond)
				return ctx
			},
			candidates: []Candidate{failing, failing},
			assert: func(t *testing.T, res Result, err error) {
				require.Error(t, err)
				require.ErrorIs(t, err, ErrNoCandidates)
			},
		},
		{
			name: "returns error when no candidates provided",
			ctx:  func() context.Context { return context.Background() },
			assert: func(t *testing.T, res Result, err error) {
				require.Error(t, err)
				require.ErrorIs(t, err, ErrNoCandidates)
			},
		},
		{
			name: "respects context cancellation",
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			candidates: []Candidate{slow},
			assert: func(t *testing.T, res Result, err error) {
				require.Error(t, err)
				require.ErrorIs(t, err, context.Canceled)
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			resolver := New(tt.candidates...)
			res, err := resolver.Resolve(tt.ctx(), "example.com")
			tt.assert(t, res, err)
		})
	}
}

func TestResolverResolveAll(t *testing.T) {
	fast := newDelayedCandidate("fast", 3*time.Millisecond, []string{"10.0.0.1"}, nil)
	slower := newDelayedCandidate("slower", 10*time.Millisecond, []string{"10.0.0.2"}, nil)
	failing := newDelayedCandidate("failing", 5*time.Millisecond, nil, errors.New("boom"))

	t.Run("collects all successes", func(t *testing.T) {
		ctx, _ := context.WithTimeout(context.Background(), time.Second)
		resolver := New(fast, slower, failing)
		results, err := resolver.ResolveAll(ctx, "example.com")
		require.NoError(t, err)
		require.Len(t, results, 2)
		sources := map[string]struct{}{}
		for _, result := range results {
			sources[result.Source] = struct{}{}
		}
		require.Contains(t, sources, "fast")
		require.Contains(t, sources, "slower")
	})

	t.Run("returns error when all fail", func(t *testing.T) {
		ctx, _ := context.WithTimeout(context.Background(), time.Second)
		resolver := New(failing, failing)
		results, err := resolver.ResolveAll(ctx, "example.com")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrNoCandidates)
		require.Empty(t, results)
	})

	t.Run("returns error when no candidates provided", func(t *testing.T) {
		ctx := context.Background()
		resolver := New()
		results, err := resolver.ResolveAll(ctx, "example.com")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrNoCandidates)
		require.Empty(t, results)
	})
}

func TestMDNSCandidate(t *testing.T) {
	ctx := context.Background()
	t.Run("returns address from query", func(t *testing.T) {
		called := false
		candidate := MDNSWithQuery("mdns", func(ctx context.Context, host string) (netip.Addr, error) {
			called = true
			return netip.MustParseAddr("192.168.1.5"), nil
		})
		resolver := New(candidate)
		res, err := resolver.Resolve(ctx, "printer.local")
		require.True(t, called)
		require.NoError(t, err)
		require.Equal(t, "mdns", res.Source)
		require.Equal(t, "printer.local", res.Host)
		require.Equal(t, []netip.Addr{netip.MustParseAddr("192.168.1.5")}, res.Addrs)
	})

	t.Run("propagates query error", func(t *testing.T) {
		errBoom := errors.New("boom")
		candidate := MDNSWithQuery("mdns", func(ctx context.Context, host string) (netip.Addr, error) {
			return netip.Addr{}, errBoom
		})
		resolver := New(candidate)
		_, err := resolver.Resolve(ctx, "printer.local")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrNoCandidates)
		require.ErrorContains(t, err, "boom")
	})

	t.Run("rejects zero address", func(t *testing.T) {
		candidate := MDNSWithQuery("mdns", func(ctx context.Context, host string) (netip.Addr, error) {
			return netip.Addr{}, nil
		})
		resolver := New(candidate)
		_, err := resolver.Resolve(ctx, "printer.local")
		require.Error(t, err)
		require.ErrorIs(t, err, ErrNoCandidates)
		require.ErrorContains(t, err, "invalid mDNS address")
	})
}

func TestResolveAnyHosts(t *testing.T) {
	// Host-sensitive candidates so we can deterministically control which host returns first.
	hostDelays1 := map[string]time.Duration{"h1": 30 * time.Millisecond, "h2": 30 * time.Millisecond}
	hostDelays2 := map[string]time.Duration{"h1": 50 * time.Millisecond, "h2": 5 * time.Millisecond}

	c1 := newHostSensitiveCandidate("c1", hostDelays1, []string{"10.0.0.10"}, nil)
	c2 := newHostSensitiveCandidate("c2", hostDelays2, []string{"10.0.0.20"}, nil)

	r := New(c1, c2)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	res, err := r.ResolveAny(ctx, []string{"h1", "h2"})
	require.NoError(t, err)
	require.Equal(t, "c2", res.Source)
	require.Equal(t, "h2", res.Host)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("10.0.0.20")}, res.Addrs)

	t.Run("all fail", func(t *testing.T) {
		fail := newHostSensitiveCandidate("f", map[string]time.Duration{"h1": 1 * time.Millisecond}, nil, errors.New("boom"))
		r := New(fail)
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		_, err := r.ResolveAny(ctx, []string{"h1", "h2"})
		require.Error(t, err)
		require.ErrorIs(t, err, ErrNoCandidates)
	})

	t.Run("no hosts", func(t *testing.T) {
		r := New(c1)
		_, err := r.ResolveAny(context.Background(), nil)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrNoCandidates)
	})
}

func newHostSensitiveCandidate(name string, delays map[string]time.Duration, ips []string, retErr error) Candidate {
	addrs := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		addrs = append(addrs, netip.MustParseAddr(ip))
	}
	return Candidate{
		Name: name,
		Lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			d := delays[host]
			if d > 0 {
				timer := time.NewTimer(d)
				defer timer.Stop()
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-timer.C:
				}
			}
			if retErr != nil {
				return nil, retErr
			}
			if len(addrs) == 0 {
				return nil, errors.New("empty result")
			}
			return append([]netip.Addr(nil), addrs...), nil
		},
	}
}

func newDelayedCandidate(name string, d time.Duration, ips []string, retErr error) Candidate {
	addrs := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		addrs = append(addrs, netip.MustParseAddr(ip))
	}
	return Candidate{
		Name: name,
		Lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			timer := time.NewTimer(d)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-timer.C:
				if retErr != nil {
					return nil, retErr
				}
				if len(addrs) == 0 {
					return nil, errors.New("empty result")
				}
				return append([]netip.Addr(nil), addrs...), nil
			}
		},
	}
}
