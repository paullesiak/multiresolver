package multiresolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

// ErrNoCandidates indicates that no resolver candidates were provided or none produced an address.
var ErrNoCandidates = errors.New("multiresolver: no candidates available")

// LookupFunc performs a host lookup for the provided name and returns zero or more network addresses.
type LookupFunc func(ctx context.Context, host string) ([]netip.Addr, error)

// Candidate ties an identifier to a lookup function so that successes and failures can be attributed to
// the source that produced them.
type Candidate struct {
	Name   string
	Lookup LookupFunc
}

// Result captures the candidate that succeeded and the addresses it resolved.
type Result struct {
	Source string
	Addrs  []netip.Addr
}

// Observer receives lifecycle notifications for each candidate execution. Implementations can expose
// metrics or logging without being hard-wired into the resolver.
type Observer interface {
	Start(name string)
	Success(name string, addrs []netip.Addr)
	Error(name string, err error)
}

// Resolver coordinates multiple lookup candidates and races them to find an answer.
type Resolver struct {
	candidates []Candidate
	observer   Observer
}

// New constructs a Resolver from the provided candidates, discarding any entries lacking a lookup
// function. It never mutates the original slice.
func New(candidates ...Candidate) *Resolver {
	kept := make([]Candidate, 0, len(candidates))
	for _, c := range candidates {
		if c.Lookup == nil {
			continue
		}
		kept = append(kept, c)
	}
	return &Resolver{candidates: kept}
}

// WithObserver registers an observer that receives callbacks during resolution. The resolver is
// returned so the helper can be chained from the call site.
func (r *Resolver) WithObserver(observer Observer) *Resolver {
	r.observer = observer
	return r
}

// Resolve races every candidate until one returns at least one address. The first successful
// result is returned immediately and the remaining lookups are cancelled. The error joins include
// ErrNoCandidates plus the underlying failures so that callers can inspect the causes.
func (r *Resolver) Resolve(ctx context.Context, host string) (Result, error) {
	if len(r.candidates) == 0 {
		return Result{}, ErrNoCandidates
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type outcome struct {
		result Result
		err    error
	}

	outcomes := make(chan outcome, len(r.candidates))
	var wg sync.WaitGroup
	for _, candidate := range r.candidates {
		c := candidate
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.notifyStart(c.Name)
			addrs, err := c.Lookup(ctx, host)
			if err != nil {
				r.notifyError(c.Name, err)
				outcomes <- outcome{err: wrapCandidateError(c.Name, err)}
				return
			}
			if len(addrs) == 0 {
				emptyErr := errors.New("no addresses returned")
				r.notifyError(c.Name, emptyErr)
				outcomes <- outcome{err: wrapCandidateError(c.Name, emptyErr)}
				return
			}
			copyAddrs := append([]netip.Addr(nil), addrs...)
			r.notifySuccess(c.Name, copyAddrs)
			outcomes <- outcome{result: Result{Source: c.Name, Addrs: copyAddrs}}
		}()
	}

	go func() {
		wg.Wait()
		close(outcomes)
	}()

	var errs []error
	for {
		select {
		case <-ctx.Done():
			return Result{}, joinErrors(errs, ctx.Err())
		case outcome, ok := <-outcomes:
			if !ok {
				return Result{}, joinErrors(errs, nil)
			}
			if outcome.err != nil {
				errs = append(errs, outcome.err)
				if len(errs) == len(r.candidates) {
					return Result{}, joinErrors(errs, nil)
				}
				continue
			}
			cancel()
			return outcome.result, nil
		}
	}
}

// ResolveAll waits for every candidate to finish and returns each successful result. The order of the
// slice reflects the time at which the answers arrived. When all candidates fail, the joined error
// includes ErrNoCandidates and the individual failures.
func (r *Resolver) ResolveAll(ctx context.Context, host string) ([]Result, error) {
	if len(r.candidates) == 0 {
		return nil, ErrNoCandidates
	}

	type outcome struct {
		result Result
		err    error
	}

	outcomes := make(chan outcome, len(r.candidates))
	var wg sync.WaitGroup
	for _, candidate := range r.candidates {
		c := candidate
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.notifyStart(c.Name)
			addrs, err := c.Lookup(ctx, host)
			if err != nil {
				r.notifyError(c.Name, err)
				outcomes <- outcome{err: wrapCandidateError(c.Name, err)}
				return
			}
			if len(addrs) == 0 {
				emptyErr := errors.New("no addresses returned")
				r.notifyError(c.Name, emptyErr)
				outcomes <- outcome{err: wrapCandidateError(c.Name, emptyErr)}
				return
			}
			copyAddrs := append([]netip.Addr(nil), addrs...)
			r.notifySuccess(c.Name, copyAddrs)
			outcomes <- outcome{result: Result{Source: c.Name, Addrs: copyAddrs}}
		}()
	}

	go func() {
		wg.Wait()
		close(outcomes)
	}()

	var (
		results []Result
		errs    []error
	)

	for outcome := range outcomes {
		if outcome.err != nil {
			errs = append(errs, outcome.err)
			continue
		}
		results = append(results, outcome.result)
	}

	if len(results) > 0 {
		return results, nil
	}

	return nil, joinErrors(errs, ctx.Err())
}

// System returns a candidate backed by the process-wide default DNS resolver.
func System(name string) Candidate {
	return LookupFromResolver(name, net.DefaultResolver)
}

// LookupFromResolver wraps a *net.Resolver so it can participate as a candidate with the provided
// name. The resolver is queried via LookupNetIP to avoid string parsing conversions.
func LookupFromResolver(name string, resolver *net.Resolver) Candidate {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return Candidate{
		Name: name,
		Lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			addrs, err := resolver.LookupNetIP(ctx, "ip", host)
			if err != nil {
				return nil, err
			}
			return append([]netip.Addr(nil), addrs...), nil
		},
	}
}

// DNSServer returns a candidate using a dedicated *net.Resolver that directs queries to the supplied
// DNS server address. Connections use Go's pure resolver stack to avoid libc lookups.
func DNSServer(name string, server netip.AddrPort) Candidate {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: time.Second}
			target := fmt.Sprintf("%s:%d", server.Addr(), server.Port())
			return dialer.DialContext(ctx, network, target)
		},
	}
	return LookupFromResolver(name, resolver)
}

func (r *Resolver) notifyStart(name string) {
	if r.observer != nil {
		r.observer.Start(name)
	}
}

func (r *Resolver) notifySuccess(name string, addrs []netip.Addr) {
	if r.observer != nil {
		r.observer.Success(name, addrs)
	}
}

func (r *Resolver) notifyError(name string, err error) {
	if r.observer != nil {
		r.observer.Error(name, err)
	}
}

func wrapCandidateError(name string, err error) error {
	if err == nil {
		return nil
	}
	if name == "" {
		return err
	}
	return fmt.Errorf("%s: %w", name, err)
}

func joinErrors(errs []error, ctxErr error) error {
	if len(errs) == 0 && ctxErr == nil {
		return ErrNoCandidates
	}

	combined := make([]error, 0, len(errs)+2)
	combined = append(combined, ErrNoCandidates)
	for _, err := range errs {
		if err != nil {
			combined = append(combined, err)
		}
	}
	if ctxErr != nil {
		combined = append(combined, ctxErr)
	}
	return errors.Join(combined...)
}
