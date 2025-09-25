# multiresolver

Race multiple hostname resolvers and return the first successful answer or all answers

- First-success: stop at the earliest valid result.
- Gather-all: wait for all candidates and return every success.
- Batteries: system DNS, custom DNS server, optional mDNS.

## Quick start

```go
package main

import (
    "context"
    "fmt"
    "net/netip"
    "time"

    "github.com/paullesiak/multiresolver"
)

func main() {
    r := multiresolver.New(
        multiresolver.System("system"),
        multiresolver.DNSServer("quad9", netip.MustParseAddrPort("9.9.9.9:53")),
        multiresolver.MDNS("mdns"),
    )

    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
    defer cancel()

    res, err := r.Resolve(ctx, "example.com")
    if err != nil {
        panic(err)
    }
    fmt.Printf("winner: %s addrs: %v\n", res.Source, res.Addrs)

    all, err := r.ResolveAll(ctx, "example.com")
    if err != nil {
        panic(err)
    }
    fmt.Printf("all: %+v\n", all)
}
```
