/*
Copyright 2021 Gravitational, Inc.

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

package db

import (
	"context"
	"io"
	"net"
	"testing"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/multiplexer"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// TestProxyProtocolPostgres ensures that clients can successfully connect to a
// Postgres database when Teleport is running behind a proxy that sends a proxy
// line.
func TestProxyProtocolPostgres(t *testing.T) {
	ctx := context.Background()
	testCtx := setupTestContext(ctx, t, withSelfHostedPostgres("postgres"))
	t.Cleanup(func() { testCtx.Close() })
	go testCtx.startHandlingConnections()

	testCtx.createUserAndRole(ctx, t, "alice", "admin", []string{"postgres"}, []string{"postgres"})

	// Point our proxy to the Teleport's db listener on the multiplexer.
	proxy, err := newTestProxy(testCtx.mux.DB().Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { proxy.Close() })
	go proxy.Serve()

	// Connect to the proxy instead of directly to Postgres listener and make
	// sure the connection succeeds.
	psql, err := testCtx.postgresClientAddr(ctx, proxy.Address(), "alice", "postgres", "postgres", "postgres")
	require.NoError(t, err)
	require.NoError(t, psql.Close(ctx))
}

// TestProxyProtocolMySQL ensures that clients can successfully connect to a
// MySQL database when Teleport is running behind a proxy that sends a proxy
// line.
func TestProxyProtocolMySQL(t *testing.T) {
	ctx := context.Background()
	testCtx := setupTestContext(ctx, t, withSelfHostedMySQL("mysql"))
	t.Cleanup(func() { testCtx.Close() })
	go testCtx.startHandlingConnections()

	testCtx.createUserAndRole(ctx, t, "alice", "admin", []string{"root"}, []string{types.Wildcard})

	// Point our proxy to the Teleport's MySQL listener.
	proxy, err := newTestProxy(testCtx.mysqlListener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { proxy.Close() })
	go proxy.Serve()

	// Connect to the proxy instead of directly to MySQL listener and make
	// sure the connection succeeds.
	mysql, err := testCtx.mysqlClientAddr(proxy.Address(), "alice", "mysql", "root")
	require.NoError(t, err)
	require.NoError(t, mysql.Close())
}

// testProxy is tcp passthrough proxy that sends a proxy-line when connecting
// to the target server.
type testProxy struct {
	listener net.Listener
	target   string
	closeCh  chan (struct{})
	log      logrus.FieldLogger
}

// newTestProxy creates a new test proxy that sends a proxy-line when
// proxying connections to the provided target address.
func newTestProxy(target string) (*testProxy, error) {
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &testProxy{
		listener: listener,
		target:   target,
		closeCh:  make(chan struct{}),
		log:      logrus.WithField(trace.Component, "test:proxy"),
	}, nil
}

// Address returns the proxy listen address.
func (p *testProxy) Address() string {
	return p.listener.Addr().String()
}

// Serve starts accepting client connections and proxying them to the target.
func (p *testProxy) Serve() error {
	for {
		clientConn, err := p.listener.Accept()
		if err != nil {
			return trace.Wrap(err)
		}
		go func() {
			if err := p.handleConnection(clientConn); err != nil {
				p.log.WithError(err).Error("Failed to handle connection.")
			}
		}()
	}
}

// handleConnection dials the target address, sends a proxy line to it and
// then starts proxying all traffic b/w client and target.
func (p *testProxy) handleConnection(clientConn net.Conn) error {
	serverConn, err := net.Dial("tcp", p.target)
	if err != nil {
		return trace.Wrap(err)
	}
	defer serverConn.Close()
	errCh := make(chan error, 2)
	go func() { // Client -> server.
		defer clientConn.Close()
		defer serverConn.Close()
		// Write proxy-line first and then start proxying from client.
		err := p.sendProxyLine(clientConn, serverConn)
		if err == nil {
			_, err = io.Copy(serverConn, clientConn)
		}
		errCh <- err
	}()
	go func() { // Server -> client.
		defer clientConn.Close()
		defer serverConn.Close()
		_, err := io.Copy(clientConn, serverConn)
		errCh <- err
	}()
	var errs []error
	for i := 0; i < 2; i++ {
		select {
		case err := <-errCh:
			if err != nil && !utils.IsOKNetworkError(err) {
				errs = append(errs, err)
			}
		case <-p.closeCh:
			p.log.Debug("Closing.")
			return trace.NewAggregate(errs...)
		}
	}
	return trace.NewAggregate(errs...)
}

// sendProxyLine sends proxy-line to the server.
func (p *testProxy) sendProxyLine(clientConn, serverConn net.Conn) error {
	clientAddr, err := utils.ParseAddr(clientConn.RemoteAddr().String())
	if err != nil {
		return trace.Wrap(err)
	}
	serverAddr, err := utils.ParseAddr(serverConn.RemoteAddr().String())
	if err != nil {
		return trace.Wrap(err)
	}
	proxyLine := &multiplexer.ProxyLine{
		Protocol:    multiplexer.TCP4,
		Source:      net.TCPAddr{IP: net.ParseIP(clientAddr.Host()), Port: clientAddr.Port(0)},
		Destination: net.TCPAddr{IP: net.ParseIP(serverAddr.Host()), Port: serverAddr.Port(0)},
	}
	_, err = serverConn.Write([]byte(proxyLine.String()))
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// Close closes the proxy listener.
func (p *testProxy) Close() error {
	close(p.closeCh)
	return p.listener.Close()
}
