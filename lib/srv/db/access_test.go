/*
Copyright 2020-2021 Gravitational, Inc.

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
	"net"
	"os"
	"testing"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/modules"
	"github.com/gravitational/teleport/lib/multiplexer"
	"github.com/gravitational/teleport/lib/reversetunnel"
	"github.com/gravitational/teleport/lib/srv/db/common"
	"github.com/gravitational/teleport/lib/srv/db/mysql"
	"github.com/gravitational/teleport/lib/srv/db/postgres"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"
	"github.com/gravitational/trace"

	"github.com/jackc/pgconn"
	"github.com/jonboulle/clockwork"
	"github.com/pborman/uuid"
	"github.com/siddontang/go-mysql/client"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	utils.InitLoggerForTests()
	os.Exit(m.Run())
}

// TestAccessPostgres verifies access scenarios to a Postgres database based
// on the configured RBAC rules.
func TestAccessPostgres(t *testing.T) {
	ctx := context.Background()
	testCtx := setupTestContext(ctx, t, withSelfHostedPostgres("postgres"))
	t.Cleanup(func() { testCtx.Close() })
	go testCtx.startHandlingConnections()

	tests := []struct {
		desc         string
		user         string
		role         string
		allowDbNames []string
		allowDbUsers []string
		dbName       string
		dbUser       string
		err          string
	}{
		{
			desc:         "has access to all database names and users",
			user:         "alice",
			role:         "admin",
			allowDbNames: []string{types.Wildcard},
			allowDbUsers: []string{types.Wildcard},
			dbName:       "postgres",
			dbUser:       "postgres",
		},
		{
			desc:         "has access to nothing",
			user:         "alice",
			role:         "admin",
			allowDbNames: []string{},
			allowDbUsers: []string{},
			dbName:       "postgres",
			dbUser:       "postgres",
			err:          "access to database denied",
		},
		{
			desc:         "no access to databases",
			user:         "alice",
			role:         "admin",
			allowDbNames: []string{},
			allowDbUsers: []string{types.Wildcard},
			dbName:       "postgres",
			dbUser:       "postgres",
			err:          "access to database denied",
		},
		{
			desc:         "no access to users",
			user:         "alice",
			role:         "admin",
			allowDbNames: []string{types.Wildcard},
			allowDbUsers: []string{},
			dbName:       "postgres",
			dbUser:       "postgres",
			err:          "access to database denied",
		},
		{
			desc:         "access allowed to specific user/database",
			user:         "alice",
			role:         "admin",
			allowDbNames: []string{"metrics"},
			allowDbUsers: []string{"alice"},
			dbName:       "metrics",
			dbUser:       "alice",
		},
		{
			desc:         "access denied to specific user/database",
			user:         "alice",
			role:         "admin",
			allowDbNames: []string{"metrics"},
			allowDbUsers: []string{"alice"},
			dbName:       "postgres",
			dbUser:       "postgres",
			err:          "access to database denied",
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			// Create user/role with the requested permissions.
			testCtx.createUserAndRole(ctx, t, test.user, test.role, test.allowDbUsers, test.allowDbNames)

			// Try to connect to the database as this user.
			pgConn, err := testCtx.postgresClient(ctx, test.user, "postgres", test.dbUser, test.dbName)
			if test.err != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), test.err)
				return
			}

			require.NoError(t, err)

			// Execute a query.
			result, err := pgConn.Exec(ctx, "select 1").ReadAll()
			require.NoError(t, err)
			require.Equal(t, []*pgconn.Result{postgres.TestQueryResponse}, result)

			// Disconnect.
			err = pgConn.Close(ctx)
			require.NoError(t, err)
		})
	}
}

// TestAccessMySQL verifies access scenarios to a MySQL database based
// on the configured RBAC rules.
func TestAccessMySQL(t *testing.T) {
	ctx := context.Background()
	testCtx := setupTestContext(ctx, t, withSelfHostedMySQL("mysql"))
	t.Cleanup(func() { testCtx.Close() })
	go testCtx.startHandlingConnections()

	tests := []struct {
		// desc is the test case description.
		desc string
		// user is the Teleport local user name the test will use.
		user string
		// role is the Teleport role name to create and assign to the user.
		role string
		// allowDbUsers is the role's list of allowed database users.
		allowDbUsers []string
		// dbUser is the database user to simulate connect as.
		dbUser string
		// err is the expected test case error.
		err string
	}{
		{
			desc:         "has access to all database users",
			user:         "alice",
			role:         "admin",
			allowDbUsers: []string{types.Wildcard},
			dbUser:       "root",
		},
		{
			desc:         "has access to nothing",
			user:         "alice",
			role:         "admin",
			allowDbUsers: []string{},
			dbUser:       "root",
			err:          "access to database denied",
		},
		{
			desc:         "access allowed to specific user",
			user:         "alice",
			role:         "admin",
			allowDbUsers: []string{"alice"},
			dbUser:       "alice",
		},
		{
			desc:         "access denied to specific user",
			user:         "alice",
			role:         "admin",
			allowDbUsers: []string{"alice"},
			dbUser:       "root",
			err:          "access to database denied",
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			// Create user/role with the requested permissions.
			testCtx.createUserAndRole(ctx, t, test.user, test.role, test.allowDbUsers, []string{types.Wildcard})

			// Try to connect to the database as this user.
			mysqlConn, err := testCtx.mysqlClient(test.user, "mysql", test.dbUser)
			if test.err != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), test.err)
				return
			}

			require.NoError(t, err)

			// Execute a query.
			result, err := mysqlConn.Execute("select 1")
			require.NoError(t, err)
			require.Equal(t, mysql.TestQueryResponse, result)

			// Disconnect.
			err = mysqlConn.Close()
			require.NoError(t, err)
		})
	}
}

type testModules struct {
	modules.Modules
}

func (m *testModules) Features() modules.Features {
	return modules.Features{
		DB: false, // Explicily turn off database access.
	}
}

// TestAccessDisabled makes sure database access can be disabled via modules.
func TestAccessDisabled(t *testing.T) {
	defaultModules := modules.GetModules()
	defer modules.SetModules(defaultModules)
	modules.SetModules(&testModules{})

	ctx := context.Background()
	testCtx := setupTestContext(ctx, t, withSelfHostedPostgres("postgres"))
	t.Cleanup(func() { testCtx.Close() })
	go testCtx.startHandlingConnections()

	userName := "alice"
	roleName := "admin"
	dbUser := "postgres"
	dbName := "postgres"

	// Create user/role with the requested permissions.
	testCtx.createUserAndRole(ctx, t, userName, roleName, []string{types.Wildcard}, []string{types.Wildcard})

	// Try to connect to the database as this user.
	_, err := testCtx.postgresClient(ctx, userName, "postgres", dbUser, dbName)
	require.Error(t, err)
	require.Contains(t, err.Error(), "this Teleport cluster doesn't support database access")
}

type testContext struct {
	hostID        string
	clusterName   string
	tlsServer     *auth.TestTLSServer
	authServer    *auth.Server
	authClient    *auth.Client
	proxyServer   *ProxyServer
	mux           *multiplexer.Mux
	mysqlListener net.Listener
	proxyConn     chan (net.Conn)
	server        *Server
	emitter       *testEmitter
	hostCA        types.CertAuthority
	// postgres is a collection of Postgres databases the test uses.
	postgres map[string]testPostgres
	// mysql is a collection of MySQL databases the test uses.
	mysql map[string]testMySQL
}

// testPostgres represents a single proxied Postgres database.
type testPostgres struct {
	// db is the test Postgres database server.
	db *postgres.TestServer
	// server is the resource representing this Postgres server.
	server types.DatabaseServer
}

// testMySQL represents a single proxied MySQL database.
type testMySQL struct {
	// db is the test MySQL database server.
	db *mysql.TestServer
	// server is the resource representing this MySQL server.
	server types.DatabaseServer
}

// startHandlingConnections starts all services required to handle database
// client connections: multiplexer, proxy server Postgres/MySQL listeners
// and the database service agent.
func (c *testContext) startHandlingConnections() {
	// Start multiplexer.
	go c.mux.Serve()
	// Start database proxy server.
	go c.proxyServer.Serve(c.mux.DB())
	// Start MySQL proxy server.
	go c.proxyServer.ServeMySQL(c.mysqlListener)
	// Start handling database client connections on the database server.
	for conn := range c.proxyConn {
		c.server.HandleConnection(conn)
	}
}

// postgresClient connects to test Postgres through database access as a
// specified Teleport user and database account.
func (c *testContext) postgresClient(ctx context.Context, teleportUser, dbService, dbUser, dbName string) (*pgconn.PgConn, error) {
	return c.postgresClientAddr(ctx, c.mux.DB().Addr().String(), teleportUser, dbService, dbUser, dbName)
}

// postgresClientAddr like postgresClient but allows to override connection address.
func (c *testContext) postgresClientAddr(ctx context.Context, address, teleportUser, dbService, dbUser, dbName string) (*pgconn.PgConn, error) {
	return postgres.MakeTestClient(ctx, common.TestClientConfig{
		AuthClient: c.authClient,
		AuthServer: c.authServer,
		Address:    address,
		Cluster:    c.clusterName,
		Username:   teleportUser,
		RouteToDatabase: tlsca.RouteToDatabase{
			ServiceName: dbService,
			Protocol:    defaults.ProtocolPostgres,
			Username:    dbUser,
			Database:    dbName,
		},
	})
}

// mysqlClient connects to test MySQL through database access as a specified
// Teleport user and database account.
func (c *testContext) mysqlClient(teleportUser, dbService, dbUser string) (*client.Conn, error) {
	return c.mysqlClientAddr(c.mysqlListener.Addr().String(), teleportUser, dbService, dbUser)
}

// mysqlClientAddr like mysqlClient but allows to override connection address.
func (c *testContext) mysqlClientAddr(address, teleportUser, dbService, dbUser string) (*client.Conn, error) {
	return mysql.MakeTestClient(common.TestClientConfig{
		AuthClient: c.authClient,
		AuthServer: c.authServer,
		Address:    address,
		Cluster:    c.clusterName,
		Username:   teleportUser,
		RouteToDatabase: tlsca.RouteToDatabase{
			ServiceName: dbService,
			Protocol:    defaults.ProtocolMySQL,
			Username:    dbUser,
		},
	})
}

// createUserAndRole creates Teleport user and role with specified names
// and allowed database users/names properties.
func (c *testContext) createUserAndRole(ctx context.Context, t *testing.T, userName, roleName string, dbUsers, dbNames []string) (types.User, types.Role) {
	user, role, err := auth.CreateUserAndRole(c.tlsServer.Auth(), userName, []string{roleName})
	require.NoError(t, err)
	role.SetDatabaseUsers(types.Allow, dbUsers)
	role.SetDatabaseNames(types.Allow, dbNames)
	err = c.tlsServer.Auth().UpsertRole(ctx, role)
	require.NoError(t, err)
	return user, role
}

// Close closes all resources associated with the test context.
func (c *testContext) Close() error {
	var errors []error
	if c.mux != nil {
		errors = append(errors, c.mux.Close())
	}
	if c.mysqlListener != nil {
		errors = append(errors, c.mysqlListener.Close())
	}
	if c.server != nil {
		errors = append(errors, c.server.Close())
	}
	return trace.NewAggregate(errors...)
}

func setupTestContext(ctx context.Context, t *testing.T, withDatabases ...withDatabaseOption) *testContext {
	testCtx := &testContext{
		clusterName: "root.example.com",
		hostID:      uuid.New(),
		postgres:    make(map[string]testPostgres),
		mysql:       make(map[string]testMySQL),
	}

	// Create multiplexer.
	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	testCtx.mux, err = multiplexer.New(multiplexer.Config{
		ID:                  "test",
		Listener:            listener,
		EnableProxyProtocol: true,
	})
	require.NoError(t, err)

	// Create MySQL proxy listener.
	testCtx.mysqlListener, err = net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	// Create and start test auth server.
	authServer, err := auth.NewTestAuthServer(auth.TestAuthServerConfig{
		Clock:       clockwork.NewFakeClockAt(time.Now()),
		ClusterName: testCtx.clusterName,
		Dir:         t.TempDir(),
	})
	require.NoError(t, err)
	testCtx.tlsServer, err = authServer.NewTestTLSServer()
	require.NoError(t, err)
	testCtx.authServer = testCtx.tlsServer.Auth()

	// Use sync recording to not involve the uploader.
	clusterConfig, err := authServer.AuthServer.GetClusterConfig()
	require.NoError(t, err)
	clusterConfig.SetSessionRecording(types.RecordAtNodeSync)
	err = authServer.AuthServer.SetClusterConfig(clusterConfig)
	require.NoError(t, err)

	// Auth client/authorizer for database service.
	testCtx.authClient, err = testCtx.tlsServer.NewClient(auth.TestServerID(teleport.RoleDatabase, testCtx.hostID))
	require.NoError(t, err)
	dbAuthorizer, err := auth.NewAuthorizer(testCtx.clusterName, testCtx.authClient, testCtx.authClient, testCtx.authClient)
	require.NoError(t, err)
	testCtx.hostCA, err = testCtx.authClient.GetCertAuthority(types.CertAuthID{Type: types.HostCA, DomainName: testCtx.clusterName}, false)
	require.NoError(t, err)

	// Auth client/authorizer for database proxy.
	proxyAuthClient, err := testCtx.tlsServer.NewClient(auth.TestBuiltin(teleport.RoleProxy))
	require.NoError(t, err)
	proxyAuthorizer, err := auth.NewAuthorizer(testCtx.clusterName, proxyAuthClient, proxyAuthClient, proxyAuthClient)
	require.NoError(t, err)

	// TLS config for database proxy and database service.
	serverIdentity, err := auth.NewServerIdentity(authServer.AuthServer, testCtx.hostID, teleport.RoleDatabase)
	require.NoError(t, err)
	tlsConfig, err := serverIdentity.TLSConfig(nil)
	require.NoError(t, err)

	// Set up database servers used by this test.
	var databaseServers []types.DatabaseServer
	for _, withDatabase := range withDatabases {
		databaseServers = append(databaseServers, withDatabase(t, ctx, testCtx))
	}

	// Establish fake reversetunnel b/w database proxy and database service.
	testCtx.proxyConn = make(chan net.Conn)
	tunnel := &reversetunnel.FakeServer{
		Sites: []reversetunnel.RemoteSite{
			&reversetunnel.FakeRemoteSite{
				Name:        testCtx.clusterName,
				ConnCh:      testCtx.proxyConn,
				AccessPoint: proxyAuthClient,
			},
		},
	}

	// Create database proxy server.
	testCtx.proxyServer, err = NewProxyServer(ctx, ProxyServerConfig{
		AuthClient:  proxyAuthClient,
		AccessPoint: proxyAuthClient,
		Authorizer:  proxyAuthorizer,
		Tunnel:      tunnel,
		TLSConfig:   tlsConfig,
	})
	require.NoError(t, err)

	// Create test audit events emitter.
	testCtx.emitter = newTestEmitter()

	// Create database service server.
	testCtx.server, err = New(ctx, Config{
		Clock:         clockwork.NewFakeClockAt(time.Now()),
		DataDir:       t.TempDir(),
		AuthClient:    testCtx.authClient,
		AccessPoint:   testCtx.authClient,
		StreamEmitter: testCtx.authClient,
		Authorizer:    dbAuthorizer,
		Servers:       databaseServers,
		TLSConfig:     tlsConfig,
		GetRotation:   func(teleport.Role) (*types.Rotation, error) { return &types.Rotation{}, nil },
		NewAuth: func(ac common.AuthConfig) (common.Auth, error) {
			// Use test auth implementation that only fakes cloud auth tokens
			// generation.
			return newTestAuth(ac)
		},
		NewAudit: func(common.AuditConfig) (common.Audit, error) {
			// Use the same audit logger implementation but substitute the
			// underlying emitter so events can be tracked in tests.
			return common.NewAudit(common.AuditConfig{
				Emitter: testCtx.emitter,
			})
		},
	})
	require.NoError(t, err)

	return testCtx
}

type withDatabaseOption func(t *testing.T, ctx context.Context, testCtx *testContext) types.DatabaseServer

func withSelfHostedPostgres(name string) withDatabaseOption {
	return func(t *testing.T, ctx context.Context, testCtx *testContext) types.DatabaseServer {
		postgresServer, err := postgres.NewTestServer(common.TestServerConfig{
			Name:       name,
			AuthClient: testCtx.authClient,
		})
		require.NoError(t, err)
		go postgresServer.Serve()
		t.Cleanup(func() { postgresServer.Close() })
		server := types.NewDatabaseServerV3(name, nil,
			types.DatabaseServerSpecV3{
				Protocol:      defaults.ProtocolPostgres,
				URI:           net.JoinHostPort("localhost", postgresServer.Port()),
				Version:       teleport.Version,
				Hostname:      teleport.APIDomain,
				HostID:        testCtx.hostID,
				DynamicLabels: dynamicLabels,
			})
		_, err = testCtx.authClient.UpsertDatabaseServer(ctx, server)
		require.NoError(t, err)
		testCtx.postgres[name] = testPostgres{
			db:     postgresServer,
			server: server,
		}
		return server
	}
}

func withRDSPostgres(name, authToken string) withDatabaseOption {
	return func(t *testing.T, ctx context.Context, testCtx *testContext) types.DatabaseServer {
		postgresServer, err := postgres.NewTestServer(common.TestServerConfig{
			Name:       name,
			AuthClient: testCtx.authClient,
			AuthToken:  authToken,
		})
		require.NoError(t, err)
		go postgresServer.Serve()
		t.Cleanup(func() { postgresServer.Close() })
		server := types.NewDatabaseServerV3(name, nil,
			types.DatabaseServerSpecV3{
				Protocol:      defaults.ProtocolPostgres,
				URI:           net.JoinHostPort("localhost", postgresServer.Port()),
				Version:       teleport.Version,
				Hostname:      teleport.APIDomain,
				HostID:        testCtx.hostID,
				DynamicLabels: dynamicLabels,
				AWS: types.AWS{
					Region: "us-east-1",
				},
				// Set CA cert, otherwise we will attempt to download RDS roots.
				CACert: testCtx.hostCA.GetTLSKeyPairs()[0].Cert,
			})
		_, err = testCtx.authClient.UpsertDatabaseServer(ctx, server)
		require.NoError(t, err)
		testCtx.postgres[name] = testPostgres{
			db:     postgresServer,
			server: server,
		}
		return server
	}
}

func withRedshiftPostgres(name, authToken string) withDatabaseOption {
	return func(t *testing.T, ctx context.Context, testCtx *testContext) types.DatabaseServer {
		postgresServer, err := postgres.NewTestServer(common.TestServerConfig{
			Name:       name,
			AuthClient: testCtx.authClient,
			AuthToken:  authToken,
		})
		require.NoError(t, err)
		go postgresServer.Serve()
		t.Cleanup(func() { postgresServer.Close() })
		server := types.NewDatabaseServerV3(name, nil,
			types.DatabaseServerSpecV3{
				Protocol:      defaults.ProtocolPostgres,
				URI:           net.JoinHostPort("localhost", postgresServer.Port()),
				Version:       teleport.Version,
				Hostname:      teleport.APIDomain,
				HostID:        testCtx.hostID,
				DynamicLabels: dynamicLabels,
				AWS: types.AWS{
					Region:   "us-east-1",
					Redshift: types.Redshift{ClusterID: "redshift-cluster-1"},
				},
				// Set CA cert, otherwise we will attempt to download Redshift roots.
				CACert: testCtx.hostCA.GetTLSKeyPairs()[0].Cert,
			})
		_, err = testCtx.authClient.UpsertDatabaseServer(ctx, server)
		require.NoError(t, err)
		testCtx.postgres[name] = testPostgres{
			db:     postgresServer,
			server: server,
		}
		return server
	}
}

func withCloudSQLPostgres(name, authToken string) withDatabaseOption {
	return func(t *testing.T, ctx context.Context, testCtx *testContext) types.DatabaseServer {
		postgresServer, err := postgres.NewTestServer(common.TestServerConfig{
			Name:       name,
			AuthClient: testCtx.authClient,
			AuthToken:  authToken,
			// Cloud SQL presented certificate must have <project-id>:<instance-id>
			// in its CN.
			CN: "project-1:instance-1",
		})
		require.NoError(t, err)
		go postgresServer.Serve()
		t.Cleanup(func() { postgresServer.Close() })
		server := types.NewDatabaseServerV3(name, nil,
			types.DatabaseServerSpecV3{
				Protocol:      defaults.ProtocolPostgres,
				URI:           net.JoinHostPort("localhost", postgresServer.Port()),
				Version:       teleport.Version,
				Hostname:      teleport.APIDomain,
				HostID:        testCtx.hostID,
				DynamicLabels: dynamicLabels,
				GCP: types.GCPCloudSQL{
					ProjectID:  "project-1",
					InstanceID: "instance-1",
				},
				// Set CA cert to pass cert validation.
				CACert: testCtx.hostCA.GetTLSKeyPairs()[0].Cert,
			})
		_, err = testCtx.authClient.UpsertDatabaseServer(ctx, server)
		require.NoError(t, err)
		testCtx.postgres[name] = testPostgres{
			db:     postgresServer,
			server: server,
		}
		return server
	}
}

func withSelfHostedMySQL(name string) withDatabaseOption {
	return func(t *testing.T, ctx context.Context, testCtx *testContext) types.DatabaseServer {
		mysqlServer, err := mysql.NewTestServer(common.TestServerConfig{
			Name:       name,
			AuthClient: testCtx.authClient,
		})
		require.NoError(t, err)
		go mysqlServer.Serve()
		t.Cleanup(func() { mysqlServer.Close() })
		server := types.NewDatabaseServerV3(name, nil,
			types.DatabaseServerSpecV3{
				Protocol:      defaults.ProtocolMySQL,
				URI:           net.JoinHostPort("localhost", mysqlServer.Port()),
				Version:       teleport.Version,
				Hostname:      teleport.APIDomain,
				HostID:        testCtx.hostID,
				DynamicLabels: dynamicLabels,
			})
		_, err = testCtx.authClient.UpsertDatabaseServer(ctx, server)
		require.NoError(t, err)
		testCtx.mysql[name] = testMySQL{
			db:     mysqlServer,
			server: server,
		}
		return server
	}
}

func withRDSMySQL(name, authUser, authToken string) withDatabaseOption {
	return func(t *testing.T, ctx context.Context, testCtx *testContext) types.DatabaseServer {
		mysqlServer, err := mysql.NewTestServer(common.TestServerConfig{
			Name:       name,
			AuthClient: testCtx.authClient,
			AuthUser:   authUser,
			AuthToken:  authToken,
		})
		require.NoError(t, err)
		go mysqlServer.Serve()
		t.Cleanup(func() { mysqlServer.Close() })
		server := types.NewDatabaseServerV3(name, nil,
			types.DatabaseServerSpecV3{
				Protocol:      defaults.ProtocolMySQL,
				URI:           net.JoinHostPort("localhost", mysqlServer.Port()),
				Version:       teleport.Version,
				Hostname:      teleport.APIDomain,
				HostID:        testCtx.hostID,
				DynamicLabels: dynamicLabels,
				AWS: types.AWS{
					Region: "us-east-1",
				},
				// Set CA cert, otherwise we will attempt to download RDS roots.
				CACert: testCtx.hostCA.GetTLSKeyPairs()[0].Cert,
			})
		_, err = testCtx.authClient.UpsertDatabaseServer(ctx, server)
		require.NoError(t, err)
		testCtx.mysql[name] = testMySQL{
			db:     mysqlServer,
			server: server,
		}
		return server
	}
}

var dynamicLabels = types.LabelsToV2(map[string]types.CommandLabel{
	"echo": &types.CommandLabelV2{
		Period:  types.NewDuration(time.Second),
		Command: []string{"echo", "test"},
	},
})
