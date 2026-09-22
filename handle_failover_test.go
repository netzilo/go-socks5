package socks5

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/things-go/go-socks5/bufferpool"
	"github.com/things-go/go-socks5/statute"
)

// multiResolver implements both NameResolver and MultiNameResolver with a
// fixed answer, in the order given.
type multiResolver struct{ ips []net.IP }

func (m multiResolver) Resolve(ctx context.Context, _ string) (context.Context, net.IP, error) {
	return ctx, m.ips[0], nil
}

func (m multiResolver) ResolveAll(ctx context.Context, _ string) (context.Context, []net.IP, error) {
	return ctx, m.ips, nil
}

// singleResolver implements only the legacy NameResolver interface.
type singleResolver struct{ ip net.IP }

func (s singleResolver) Resolve(ctx context.Context, _ string) (context.Context, net.IP, error) {
	return ctx, s.ip, nil
}

// recordingDial records every address attempted and delegates to fn.
type recordingDial struct {
	mu    sync.Mutex
	addrs []string
	fn    func(ctx context.Context, addr string) (net.Conn, error)
}

func (r *recordingDial) dial(ctx context.Context, _ string, addr string) (net.Conn, error) {
	r.mu.Lock()
	r.addrs = append(r.addrs, addr)
	r.mu.Unlock()
	return r.fn(ctx, addr)
}

func (r *recordingDial) attempted() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.addrs...)
}

// startPingPong starts a TCP echo that expects "ping" and answers "pong".
func startPingPong(t *testing.T) *net.TCPAddr {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4)
				if _, err := io.ReadAtLeast(c, buf, 4); err == nil && bytes.Equal(buf, []byte("ping")) {
					c.Write([]byte("pong")) //nolint: errcheck
				}
			}(conn)
		}
	}()
	return l.Addr().(*net.TCPAddr)
}

// fqdnConnectRequest builds a SOCKS5 CONNECT to a domain name followed by "ping".
func fqdnConnectRequest(name string, port int) *bytes.Buffer {
	buf := bytes.NewBuffer([]byte{statute.VersionSocks5, statute.CommandConnect, 0, statute.ATYPDomain, byte(len(name))})
	buf.WriteString(name)
	buf.Write([]byte{byte(port >> 8), byte(port)})
	buf.WriteString("ping")
	return buf
}

func newTestServer(res NameResolver, dial func(ctx context.Context, network, addr string) (net.Conn, error), attempt time.Duration) *Server {
	return &Server{
		rules:              NewPermitAll(),
		resolver:           res,
		dial:               dial,
		dialAttemptTimeout: attempt,
		logger:             NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags)),
		bufferPool:         bufferpool.NewPool(32 * 1024),
	}
}

// gatedReader yields the request bytes, then blocks on EOF until released —
// like a real client that keeps its socket open until it has read the reply.
// Without this, bytes.Buffer hits EOF immediately and the server closes the
// target before "pong" is relayed (the same race that affects TestRequest_Connect).
type gatedReader struct {
	r       io.Reader
	release chan struct{}
}

func (g *gatedReader) Read(p []byte) (int, error) {
	n, err := g.r.Read(p)
	if err == io.EOF {
		<-g.release
	}
	return n, err
}

// syncConn is a goroutine-safe MockConn that can wait for a byte suffix.
type syncConn struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncConn) Write(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(b)
}

func (s *syncConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: []byte{127, 0, 0, 1}, Port: 65432}
}

func (s *syncConn) bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.buf.Bytes()...)
}

func (s *syncConn) waitForSuffix(t *testing.T, suffix string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if bytes.HasSuffix(s.bytes(), []byte(suffix)) {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %q; got %x", suffix, s.bytes())
}

// runConnect drives handleRequest against a gated client and returns the
// bytes written back to the client once "pong" has arrived.
func runConnect(t *testing.T, srv *Server, reqBytes *bytes.Buffer, expectPong bool) ([]byte, *Request, error) {
	release := make(chan struct{})
	req, err := ParseRequest(&gatedReader{r: reqBytes, release: release})
	require.NoError(t, err)
	rsp := new(syncConn)

	done := make(chan error, 1)
	go func() { done <- srv.handleRequest(rsp, req) }()

	if expectPong {
		rsp.waitForSuffix(t, "pong", 5*time.Second)
	}
	close(release)
	select {
	case err = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("handleRequest did not return")
	}
	return rsp.bytes(), req, err
}

func requireSuccessReplyWithPong(t *testing.T, out []byte) {
	require.GreaterOrEqual(t, len(out), 10+4)
	require.Equal(t, statute.VersionSocks5, out[0])
	require.Equal(t, statute.RepSuccess, out[1], "expected RepSuccess, got reply code %d", out[1])
	require.Equal(t, []byte("pong"), out[len(out)-4:])
}

// The customer scenario: the resolver puts an unreachable address first (an
// AAAA record on a host without IPv6 egress). The CONNECT must fall through to
// the next candidate instead of failing with RepHostUnreachable.
func TestRequest_Connect_FQDN_FailsOverToNextCandidate(t *testing.T) {
	target := startPingPong(t)
	dead := net.ParseIP("2001:db8::1")

	rd := &recordingDial{fn: func(ctx context.Context, addr string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(addr)
		if host == dead.String() {
			return nil, errors.New("connectex: connection attempt failed")
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}}
	srv := newTestServer(multiResolver{ips: []net.IP{dead, target.IP}}, rd.dial, 0)

	out, req, err := runConnect(t, srv, fqdnConnectRequest("travel.example", target.Port), true)
	require.NoError(t, err)

	requireSuccessReplyWithPong(t, out)
	port := strconv.Itoa(target.Port)
	require.Equal(t, []string{
		net.JoinHostPort(dead.String(), port),
		net.JoinHostPort(target.IP.String(), port),
	}, rd.attempted(), "must try candidates in resolver order and stop at the first success")
	require.Equal(t, []net.IP{dead, target.IP}, req.Candidates)
}

// A candidate that black-holes (SYN never answered) must be cut off by the
// per-attempt timeout so the next candidate is reached quickly.
func TestRequest_Connect_FQDN_AttemptTimeoutBoundsHangingCandidate(t *testing.T) {
	target := startPingPong(t)
	blackhole := net.ParseIP("10.255.255.1")

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	rd := &recordingDial{fn: func(ctx context.Context, addr string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(addr)
		if host == blackhole.String() {
			<-release // black hole: never answers while the test runs
			return nil, errors.New("abandoned")
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}}
	const attempt = 150 * time.Millisecond
	srv := newTestServer(multiResolver{ips: []net.IP{blackhole, target.IP}}, rd.dial, attempt)

	start := time.Now()
	out, _, err := runConnect(t, srv, fqdnConnectRequest("travel.example", target.Port), true)
	elapsed := time.Since(start)
	require.NoError(t, err)

	requireSuccessReplyWithPong(t, out)
	require.GreaterOrEqual(t, elapsed, attempt, "first candidate should have consumed the attempt budget")
	require.Less(t, elapsed, 10*attempt, "hanging candidate must not block beyond the attempt timeout")
	require.Len(t, rd.attempted(), 2)
}

// A dialer may return a connection immediately and keep using ctx afterwards
// (the MITM wrapper returns a pipe and dials upstream asynchronously). The
// context handed to the winning attempt must therefore stay live: no deadline,
// not cancelled — even though the attempt was not the last candidate.
func TestRequest_Connect_FQDN_WinnerContextStaysLive(t *testing.T) {
	const attempt = 30 * time.Millisecond
	ips := []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")}

	type probe struct {
		hadDeadline bool
		errAfter    error
	}
	probeCh := make(chan probe, 1)
	dial := func(ctx context.Context, _ string, _ string) (net.Conn, error) {
		clientSide, serverSide := net.Pipe()
		go func() {
			// Serve ping/pong like an upstream would, but only after the attempt
			// window has long expired — if ctx were bounded it would be dead now.
			time.Sleep(4 * attempt)
			_, hadDeadline := ctx.Deadline()
			probeCh <- probe{hadDeadline: hadDeadline, errAfter: ctx.Err()}
			buf := make([]byte, 4)
			if _, err := io.ReadFull(clientSide, buf); err == nil {
				clientSide.Write([]byte("pong")) //nolint: errcheck
			}
			clientSide.Close()
		}()
		return &tcpAddrPipe{Conn: serverSide}, nil
	}
	srv := newTestServer(multiResolver{ips: ips}, dial, attempt)

	out, _, err := runConnect(t, srv, fqdnConnectRequest("travel.example", 443), true)
	require.NoError(t, err)
	requireSuccessReplyWithPong(t, out)
	p := <-probeCh
	require.False(t, p.hadDeadline, "winning attempt's ctx must carry no deadline")
	require.NoError(t, p.errAfter, "winning attempt's ctx must not be cancelled after the dial returns")
}

// tcpAddrPipe gives a net.Pipe end a *net.TCPAddr LocalAddr so SendReply can
// encode the SOCKS5 success reply (mirrors the MITM wrapper's shim).
type tcpAddrPipe struct{ net.Conn }

func (c *tcpAddrPipe) LocalAddr() net.Addr  { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (c *tcpAddrPipe) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

// An attempt that completes after it was abandoned must have its connection
// closed rather than leaked, and the next candidate must have been used.
func TestRequest_Connect_FQDN_LateSuccessIsClosed(t *testing.T) {
	target := startPingPong(t)
	const attempt = 40 * time.Millisecond
	slow := net.ParseIP("192.0.2.1")

	lateEnd := make(chan net.Conn, 1)
	rd := &recordingDial{fn: func(ctx context.Context, addr string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(addr)
		if host == slow.String() {
			time.Sleep(4 * attempt) // answers, but far too late
			a, b := net.Pipe()
			lateEnd <- b
			return a, nil
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}}
	srv := newTestServer(multiResolver{ips: []net.IP{slow, target.IP}}, rd.dial, attempt)

	out, _, err := runConnect(t, srv, fqdnConnectRequest("travel.example", target.Port), true)
	require.NoError(t, err)
	requireSuccessReplyWithPong(t, out)
	require.Len(t, rd.attempted(), 2)

	// The abandoned attempt's connection must be closed by the server.
	other := <-lateEnd
	other.SetReadDeadline(time.Now().Add(2 * time.Second)) //nolint: errcheck
	_, rerr := other.Read(make([]byte, 1))
	require.ErrorIs(t, rerr, io.EOF, "late connection must be closed, not leaked")
}

// The last candidate must not be bounded by the attempt timeout: a slow but
// reachable destination gets the request's full context.
func TestRequest_Connect_FQDN_LastCandidateGetsFullContext(t *testing.T) {
	target := startPingPong(t)
	first := net.ParseIP("192.0.2.1")

	var lastHadDeadline bool
	rd := &recordingDial{fn: func(ctx context.Context, addr string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(addr)
		if host == first.String() {
			return nil, errors.New("refused")
		}
		_, lastHadDeadline = ctx.Deadline()
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}}
	srv := newTestServer(multiResolver{ips: []net.IP{first, target.IP}}, rd.dial, 50*time.Millisecond)

	out, _, err := runConnect(t, srv, fqdnConnectRequest("travel.example", target.Port), true)
	require.NoError(t, err)
	requireSuccessReplyWithPong(t, out)
	require.False(t, lastHadDeadline, "last candidate must be dialed with the unbounded request context")
}

// When every candidate fails the client still gets a proper SOCKS5 error reply
// and the returned error names the destination.
func TestRequest_Connect_FQDN_AllCandidatesFail(t *testing.T) {
	rd := &recordingDial{fn: func(ctx context.Context, addr string) (net.Conn, error) {
		return nil, errors.New("connectex: connection attempt failed")
	}}
	ips := []net.IP{net.ParseIP("2001:db8::1"), net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")}
	srv := newTestServer(multiResolver{ips: ips}, rd.dial, 0)

	req, err := ParseRequest(fqdnConnectRequest("travel.example", 443))
	require.NoError(t, err)
	rsp := new(MockConn)
	err = srv.handleRequest(rsp, req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "connect to")

	out := rsp.buf.Bytes()
	require.Equal(t, statute.RepHostUnreachable, out[1])
	require.Len(t, rd.attempted(), 3, "every candidate must be tried before giving up")
}

// Resolvers that only implement the legacy single-IP interface keep the exact
// previous behaviour: one dial, no candidates recorded.
func TestRequest_Connect_FQDN_SingleIPResolverUnchanged(t *testing.T) {
	target := startPingPong(t)
	rd := &recordingDial{fn: func(ctx context.Context, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}}
	srv := newTestServer(singleResolver{ip: target.IP}, rd.dial, time.Second)

	out, req, err := runConnect(t, srv, fqdnConnectRequest("travel.example", target.Port), true)
	require.NoError(t, err)
	requireSuccessReplyWithPong(t, out)
	require.Empty(t, req.Candidates)
	require.Len(t, rd.attempted(), 1)
}

// A MultiNameResolver that answers with an empty list must surface as a
// resolution failure, not a nil-IP dial.
func TestRequest_Connect_FQDN_EmptyResolveAllIsResolutionFailure(t *testing.T) {
	rd := &recordingDial{fn: func(ctx context.Context, addr string) (net.Conn, error) {
		t.Fatalf("dial must not be called, got %s", addr)
		return nil, nil
	}}
	srv := newTestServer(multiResolver{ips: nil}, rd.dial, 0)
	// multiResolver.Resolve would index ips[0]; make sure the multi path is taken.
	req, err := ParseRequest(fqdnConnectRequest("travel.example", 443))
	require.NoError(t, err)
	rsp := new(MockConn)
	err = srv.handleRequest(rsp, req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to resolve destination")
	require.Equal(t, statute.RepHostUnreachable, rsp.buf.Bytes()[1])
}

// rewriteTo replaces the destination with a fixed address.
type rewriteTo struct{ to *statute.AddrSpec }

func (r rewriteTo) Rewrite(ctx context.Context, _ *Request) (context.Context, *statute.AddrSpec) {
	return ctx, r.to
}

// A rewriter that changes the destination takes precedence: the resolver's
// candidates for the original name must not be dialed.
func TestRequest_Connect_FQDN_RewrittenDestIgnoresCandidates(t *testing.T) {
	target := startPingPong(t)
	rd := &recordingDial{fn: func(ctx context.Context, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}}
	srv := newTestServer(multiResolver{ips: []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")}}, rd.dial, 0)
	srv.rewriter = rewriteTo{to: &statute.AddrSpec{IP: target.IP, Port: target.Port, AddrType: statute.ATYPIPv4}}

	out, _, err := runConnect(t, srv, fqdnConnectRequest("travel.example", 443), true)
	require.NoError(t, err)
	requireSuccessReplyWithPong(t, out)
	require.Equal(t, []string{net.JoinHostPort(target.IP.String(), strconv.Itoa(target.Port))}, rd.attempted())
}

// Literal-IP CONNECTs never go through the resolver and have no candidates.
func TestRequest_Connect_LiteralIP_NoCandidates(t *testing.T) {
	target := startPingPong(t)
	rd := &recordingDial{fn: func(ctx context.Context, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}}
	srv := newTestServer(multiResolver{ips: []net.IP{net.ParseIP("192.0.2.1")}}, rd.dial, time.Second)

	buf := bytes.NewBuffer([]byte{statute.VersionSocks5, statute.CommandConnect, 0,
		statute.ATYPIPv4, 127, 0, 0, 1, byte(target.Port >> 8), byte(target.Port)})
	buf.WriteString("ping")
	out, req, err := runConnect(t, srv, buf, true)
	require.NoError(t, err)
	requireSuccessReplyWithPong(t, out)
	require.Empty(t, req.Candidates)
	require.Len(t, rd.attempted(), 1)
}

// WithDialAttemptTimeout must wire the field through NewServer.
func TestWithDialAttemptTimeout(t *testing.T) {
	s := NewServer(WithDialAttemptTimeout(3 * time.Second))
	require.Equal(t, 3*time.Second, s.dialAttemptTimeout)
	require.Zero(t, NewServer().dialAttemptTimeout)
}
