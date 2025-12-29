package oidc

import (
	"context"
	"net/http"
	"reflect"
	"sync"
)

type Manager struct {
	mu         sync.Mutex
	cache      map[string]*providerEntry
	httpClient *http.Client
}

type providerEntry struct {
	config   ProviderConfig
	provider Provider
}

func NewManager(httpClient *http.Client) *Manager {
	return &Manager{
		cache:      make(map[string]*providerEntry),
		httpClient: httpClient,
	}
}

func (m *Manager) Provider(ctx context.Context, config ProviderConfig) (Provider, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if entry, ok := m.cache[config.Name]; ok {
		if reflect.DeepEqual(entry.config, config) {
			return entry.provider, nil
		}
	}

	provider, err := newProvider(ctx, m.httpClient, config)
	if err != nil {
		return nil, err
	}
	m.cache[config.Name] = &providerEntry{
		config:   config,
		provider: provider,
	}
	return provider, nil
}
