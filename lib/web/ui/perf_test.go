/*
Copyright 2020 Gravitational, Inc.

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

package ui

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/backend/lite"
	"github.com/gravitational/teleport/lib/backend/memory"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/reversetunnel"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/services/local"

	"github.com/pborman/uuid"
	"github.com/stretchr/testify/assert"
)

const clusterName = "bench.example.com"

func BenchmarkGetClusterDetails(b *testing.B) {
	ctx := context.Background()

	const authCount = 6
	const proxyCount = 6

	type testCase struct {
		validation, memory bool
		nodes              int
	}

	var tts []testCase

	for _, validation := range []bool{true, false} {
		for _, memory := range []bool{true, false} {
			for _, nodes := range []int{100, 1000, 10000} {
				tts = append(tts, testCase{
					validation: validation,
					memory:     memory,
					nodes:      nodes,
				})
			}
		}
	}

	for _, tt := range tts {
		// create a descriptive name for the sub-benchmark.
		name := fmt.Sprintf("tt(validation=%v,memory=%v,nodes=%d)", tt.validation, tt.memory, tt.nodes)

		// run the sub benchmark
		b.Run(name, func(sb *testing.B) {

			sb.StopTimer() // stop timer while running setup

			// set up marshal options
			var opts []services.MarshalOption
			if !tt.validation {
				opts = append(opts, services.SkipValidation())
			}

			// configure the backend instance
			var bk backend.Backend
			var err error
			if tt.memory {
				bk, err = memory.New(memory.Config{})
				assert.NoError(b, err)
			} else {
				dir, err := ioutil.TempDir("", "teleport")
				assert.NoError(b, err)
				defer os.RemoveAll(dir)

				bk, err = lite.NewWithConfig(context.TODO(), lite.Config{
					Path: dir,
				})
				assert.NoError(b, err)
			}
			defer bk.Close()

			svc := local.NewPresenceService(bk)

			// seed the test nodes
			insertServers(ctx, b, svc, services.KindNode, tt.nodes)
			insertServers(ctx, b, svc, services.KindProxy, proxyCount)
			insertServers(ctx, b, svc, services.KindAuthServer, authCount)

			site := &mockRemoteSite{
				accessPoint: &mockAccessPoint{
					presence: svc,
				},
			}

			sb.StartTimer() // restart timer for benchmark operations

			benchmarkGetClusterDetails(ctx, sb, site, tt.nodes, opts...)

			sb.StopTimer() // stop timer to exclude deferred cleanup
		})
	}
}

// insertServers inserts a collection of servers into a backend.
func insertServers(ctx context.Context, t assert.TestingT, svc services.Presence, kind string, count int) {
	const labelCount = 10
	labels := make(map[string]string, labelCount)
	for i := 0; i < labelCount; i++ {
		labels[fmt.Sprintf("label-key-%d", i)] = fmt.Sprintf("label-val-%d", i)
	}
	for i := 0; i < count; i++ {
		name := uuid.New()
		addr := fmt.Sprintf("%s.%s", name, clusterName)
		server := &services.ServerV2{
			Kind:    kind,
			Version: services.V2,
			Metadata: services.Metadata{
				Name:      name,
				Namespace: defaults.Namespace,
				Labels:    labels,
			},
			Spec: services.ServerSpecV2{
				Addr:       addr,
				PublicAddr: addr,
				Version:    teleport.Version,
			},
		}
		var err error
		switch kind {
		case services.KindNode:
			_, err = svc.UpsertNode(ctx, server)
		case services.KindProxy:
			err = svc.UpsertProxy(server)
		case services.KindAuthServer:
			err = svc.UpsertAuthServer(server)
		default:
			t.Errorf("Unexpected server kind: %s", kind)
		}
		assert.NoError(t, err)
	}
}

func benchmarkGetClusterDetails(ctx context.Context, b *testing.B, site reversetunnel.RemoteSite, nodes int, opts ...services.MarshalOption) {
	var cluster *Cluster
	var err error
	for i := 0; i < b.N; i++ {
		cluster, err = GetClusterDetails(ctx, site, opts...)
		assert.NoError(b, err)
	}
	assert.NotNil(b, cluster)
	assert.Equal(b, nodes, cluster.NodeCount)
}

type mockRemoteSite struct {
	reversetunnel.RemoteSite
	accessPoint auth.AccessPoint
}

func (m *mockRemoteSite) CachingAccessPoint() (auth.AccessPoint, error) {
	return m.accessPoint, nil
}

func (m *mockRemoteSite) GetName() string {
	return clusterName
}

func (m *mockRemoteSite) GetLastConnected() time.Time {
	return time.Now()
}

func (m *mockRemoteSite) GetStatus() string {
	return teleport.RemoteClusterStatusOnline
}

type mockAccessPoint struct {
	auth.AccessPoint
	presence *local.PresenceService
}

func (m *mockAccessPoint) GetNodes(ctx context.Context, namespace string, opts ...services.MarshalOption) ([]services.Server, error) {
	return m.presence.GetNodes(ctx, namespace, opts...)
}

func (m *mockAccessPoint) GetProxies() ([]services.Server, error) {
	return m.presence.GetProxies()
}

func (m *mockAccessPoint) GetAuthServers() ([]services.Server, error) {
	return m.presence.GetAuthServers()
}
