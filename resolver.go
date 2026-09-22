package socks5

import (
	"context"
	"net"
)

// NameResolver is used to implement custom name resolution
type NameResolver interface {
	Resolve(ctx context.Context, name string) (context.Context, net.IP, error)
}

// MultiNameResolver may optionally be implemented by a NameResolver to return
// every address for a name, in the order they should be attempted. When the
// configured resolver implements it, CONNECT requests fail over between the
// returned addresses instead of committing to a single one.
type MultiNameResolver interface {
	ResolveAll(ctx context.Context, name string) (context.Context, []net.IP, error)
}

// DNSResolver uses the system DNS to resolve host names
type DNSResolver struct{}

// Resolve implement interface NameResolver
func (d DNSResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	addr, err := net.ResolveIPAddr("ip", name)
	if err != nil {
		return ctx, nil, err
	}
	return ctx, addr.IP, err
}
