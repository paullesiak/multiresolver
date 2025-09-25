package multiresolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
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
	// Host is the hostname that produced this result.
	Host string
	// Source is the candidate (resolver name) that resolved Host.
	Source string
	// Addrs are the resolved addresses for Host.
	Addrs []netip.Addr
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

	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	resultCh := make(chan Result, len(r.candidates))
	errCh := make(chan error, len(r.candidates))

	for i := range r.candidates {
		go r.runCandidate(subCtx, host, r.candidates[i], resultCh, errCh)
	}

	var errs []error
	for {
		select {
		case <-ctx.Done():
			return Result{}, joinErrors(errs, ctx.Err())
		case res := <-resultCh:
			cancel()
			return res, nil
		case err := <-errCh:
			errs = append(errs, err)
			if len(errs) == len(r.candidates) {
				return Result{}, joinErrors(errs, nil)
			}
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

	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	resultCh := make(chan Result, len(r.candidates))
	errCh := make(chan error, len(r.candidates))

	for i := range r.candidates {
		go r.runCandidate(subCtx, host, r.candidates[i], resultCh, errCh)
	}

	var (
		results    []Result
		errs       []error
		finished   int
		targetRuns = len(r.candidates)
	)

	for finished < targetRuns {
		select {
		case <-ctx.Done():
			return nil, joinErrors(errs, ctx.Err())
		case res := <-resultCh:
			results = append(results, res)
			finished++
		case err := <-errCh:
			errs = append(errs, err)
			finished++
		}
	}

	if len(results) > 0 {
		return results, nil
	}

	return nil, joinErrors(errs, nil)
}

// ResolveAny races all candidates across all provided hosts and returns the first
// successful result. When hosts or candidates are empty, or when all lookups fail,
// an error joined with ErrNoCandidates is returned.
func (r *Resolver) ResolveAny(ctx context.Context, hosts []string) (Result, error) {
	if len(r.candidates) == 0 || len(hosts) == 0 {
		return Result{}, ErrNoCandidates
	}

	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	resultCh := make(chan Result, len(r.candidates)*len(hosts))
	errCh := make(chan error, len(r.candidates)*len(hosts))

	for _, h := range hosts {
		host := h
		for i := range r.candidates {
			go r.runCandidate(subCtx, host, r.candidates[i], resultCh, errCh)
		}
	}

	var errs []error
	total := len(r.candidates) * len(hosts)
	failed := 0
	for {
		select {
		case <-ctx.Done():
			return Result{}, joinErrors(errs, ctx.Err())
		case res := <-resultCh:
			cancel()
			return res, nil
		case err := <-errCh:
			errs = append(errs, err)
			failed++
			if failed == total {
				return Result{}, joinErrors(errs, nil)
			}
		}
	}
}

func (r *Resolver) runCandidate(ctx context.Context, host string, candidate Candidate, resultCh chan<- Result, errCh chan<- error) {
	if candidate.Lookup == nil {
		return
	}

	if ctx.Err() != nil {
		return
	}

	r.notifyStart(candidate.Name)

	addrs, err := candidate.Lookup(ctx, host)
	if err != nil {
		r.notifyError(candidate.Name, err)
		r.safeSendError(ctx, errCh, wrapCandidateError(candidate.Name, err))
		return
	}

	if len(addrs) == 0 {
		emptyErr := errors.New("no addresses returned")
		r.notifyError(candidate.Name, emptyErr)
		r.safeSendError(ctx, errCh, wrapCandidateError(candidate.Name, emptyErr))
		return
	}

	copyAddrs := append([]netip.Addr(nil), addrs...)
	r.notifySuccess(candidate.Name, copyAddrs)
	r.safeSendResult(ctx, resultCh, Result{Host: host, Source: candidate.Name, Addrs: copyAddrs})
}

func (r *Resolver) safeSendResult(ctx context.Context, ch chan<- Result, res Result) {
	select {
	case ch <- res:
	case <-ctx.Done():
	}
}

func (r *Resolver) safeSendError(ctx context.Context, ch chan<- error, err error) {
	if err == nil {
		return
	}
	select {
	case ch <- err:
	case <-ctx.Done():
	}
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
