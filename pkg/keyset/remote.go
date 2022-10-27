package keyset

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"
	"io"
	"mime"
	"net/http"
	"sync"
	"time"
)

func newRemote(jwksURL string, now func() time.Time) *Remote {
	if now == nil {
		now = time.Now
	}
	return &Remote{jwksURL: jwksURL, ctx: context.Background(), now: now}
}

// Remote is a KeySet implementation that validates JSON web tokens against
// a jwks_uri endpoint.
type Remote struct {
	jwksURL    string
	ctx        context.Context
	now        func() time.Time
	mu         sync.RWMutex
	inflight   *inflight
	cachedKeys []jose.JSONWebKey
}

type inflight struct {
	doneCh chan struct{}
	keys   []jose.JSONWebKey
	err    error
}

func newInflight() *inflight {
	return &inflight{doneCh: make(chan struct{})}
}

// wait returns a channel that multiple goroutines can receive on. Once it returns
// a value, the inflight request is done and result() can be inspected.
func (i *inflight) wait() <-chan struct{} {
	return i.doneCh
}

// done can only be called by a single goroutine. It records the result of the
// inflight request and signals other goroutines that the result is safe to
// inspect.
func (i *inflight) done(keys []jose.JSONWebKey, err error) {
	i.keys = keys
	i.err = err
	close(i.doneCh)
}

// result cannot be called until the wait() channel has returned a value.
func (i *inflight) result() ([]jose.JSONWebKey, error) {
	return i.keys, i.err
}

func (r *Remote) Verify(jws *jose.JSONWebSignature) ([]byte, error) {
	// We don't support JWTs signed with multiple signatures.
	keyID := ""
	for _, sig := range jws.Signatures {
		keyID = sig.Header.KeyID
		break
	}

	keys := r.keysFromCache()
	for _, key := range keys {
		if keyID == "" || key.KeyID == keyID {
			if payload, err := jws.Verify(&key); err == nil {
				return payload, nil
			}
		}
	}

	// If the kid doesn't match, check for new keys from the remote. This is the
	// strategy recommended by the spec.
	//
	// https://openid.net/specs/openid-connect-core-1_0.html#RotateSigKeys
	keys, err := r.keysFromRemote(r.ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching keys %v", err)
	}

	for _, key := range keys {
		if keyID == "" || key.KeyID == keyID {
			if payload, err := jws.Verify(&key); err == nil {
				return payload, nil
			}
		}
	}
	return nil, errors.New("failed to verify id token signature")
}

func (r *Remote) keysFromCache() (keys []jose.JSONWebKey) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cachedKeys
}

// keysFromRemote syncs the key set from the remote set, records the values in the
// cache, and returns the key set.
func (r *Remote) keysFromRemote(ctx context.Context) ([]jose.JSONWebKey, error) {
	// Need to lock to inspect the inflight request field.
	r.mu.Lock()
	// If there's not a current inflight request, create one.
	if r.inflight == nil {
		r.inflight = newInflight()

		// This goroutine has exclusive ownership over the current inflight
		// request. It releases the resource by nil'ing the inflight field
		// once the goroutine is done.
		go func() {
			// Sync keys and finish inflight when that's done.
			keys, err := r.updateKeys()

			r.inflight.done(keys, err)

			// Lock to update the keys and indicate that there is no longer an
			// inflight request.
			r.mu.Lock()
			defer r.mu.Unlock()

			if err == nil {
				r.cachedKeys = keys
			}

			// Free inflight so a different request can run.
			r.inflight = nil
		}()
	}
	inflight := r.inflight
	r.mu.Unlock()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-inflight.wait():
		return inflight.result()
	}
}

func (r *Remote) updateKeys() ([]jose.JSONWebKey, error) {
	req, err := http.NewRequest("GET", r.jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc: can't create request: %v", err)
	}

	resp, err := doRequest(r.ctx, req)
	if err != nil {
		return nil, fmt.Errorf("oidc: get keys failed %v", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc: get keys failed: %s %s", resp.Status, body)
	}

	var keySet jose.JSONWebKeySet
	err = unmarshalResp(resp, body, &keySet)
	if err != nil {
		return nil, fmt.Errorf("oidc: failed to decode keys: %v %s", err, body)
	}
	return keySet.Keys, nil
}

func doRequest(ctx context.Context, req *http.Request) (*http.Response, error) {
	client := http.DefaultClient
	if c, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok {
		client = c
	}
	return client.Do(req.WithContext(ctx))
}

func unmarshalResp(r *http.Response, body []byte, v interface{}) error {
	err := json.Unmarshal(body, &v)
	if err == nil {
		return nil
	}
	ct := r.Header.Get("Content-Type")
	mediaType, _, parseErr := mime.ParseMediaType(ct)
	if parseErr == nil && mediaType == "application/json" {
		return fmt.Errorf("got Content-Type = application/json, but could not unmarshal as JSON: %v", err)
	}
	return fmt.Errorf("expected Content-Type = application/json, got %q: %v", ct, err)
}
