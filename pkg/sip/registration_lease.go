// Copyright 2026 LiveKit, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sip

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/livekit/protocol/logger"
	"github.com/livekit/sip/pkg/config"
	"github.com/livekit/sip/pkg/stats"
	"github.com/redis/go-redis/v9"
)

const (
	registrationLeaseTTL        = 30 * time.Second
	registrationLeaseRenewal    = registrationLeaseTTL / 3
	registrationLeaseRetry      = 2 * time.Second
	registrationLeaseRPCTimeout = 2 * time.Second
)

var (
	errRegistrationLeaseLost     = errors.New("SIP registration ownership lease was lost")
	registrationLeaseRenewScript = redis.NewScript(`
if redis.call("GET", KEYS[1]) ~= ARGV[1] then
	return 0
end
return redis.call("PEXPIRE", KEYS[1], ARGV[2])
`)
	registrationLeaseReleaseScript = redis.NewScript(`
if redis.call("GET", KEYS[1]) ~= ARGV[1] then
	return 0
end
return redis.call("DEL", KEYS[1])
`)
)

// RegistrationLeaseStore arbitrates ownership of one carrier AOR across SIP
// replicas. Implementations must compare the opaque token atomically on renew
// and release; an owner name alone is not sufficient after process restarts.
type RegistrationLeaseStore interface {
	Acquire(ctx context.Context, key, token string, ttl time.Duration) (bool, error)
	Renew(ctx context.Context, key, token string, ttl time.Duration) (bool, error)
	Release(ctx context.Context, key, token string) error
}

type redisRegistrationLeaseStore struct {
	client redis.UniversalClient
}

// NewRedisRegistrationLeaseStore creates the shared ownership store used by
// every SIP node in one ABIA Realtime cluster.
func NewRedisRegistrationLeaseStore(client redis.UniversalClient) RegistrationLeaseStore {
	if client == nil {
		return nil
	}
	return &redisRegistrationLeaseStore{client: client}
}

func (s *redisRegistrationLeaseStore) Acquire(ctx context.Context, key, token string, ttl time.Duration) (bool, error) {
	return s.client.SetNX(ctx, key, token, ttl).Result()
}

func (s *redisRegistrationLeaseStore) Renew(ctx context.Context, key, token string, ttl time.Duration) (bool, error) {
	result, err := registrationLeaseRenewScript.Run(ctx, s.client, []string{key}, token, ttl.Milliseconds()).Int64()
	return result == 1, err
}

func (s *redisRegistrationLeaseStore) Release(ctx context.Context, key, token string) error {
	return registrationLeaseReleaseScript.Run(ctx, s.client, []string{key}, token).Err()
}

type registrationOwner struct {
	log       logger.Logger
	store     RegistrationLeaseStore
	key       string
	ownerID   string
	makeOwner func() (*registrant, error)
	mon       *stats.Monitor

	startOnce sync.Once
	stopOnce  sync.Once
	stop      chan struct{}
	done      chan struct{}
	mu        sync.Mutex
	deadline  time.Time
}

func newRegistrationOwner(
	log logger.Logger,
	store RegistrationLeaseStore,
	ownerID string,
	clusterID string,
	rc config.SIPRegistrationConfig,
	makeOwner func() (*registrant, error),
	mon *stats.Monitor,
) (*registrationOwner, error) {
	if store == nil {
		return nil, errors.New("SIP registrations require the shared Redis ownership store")
	}
	if strings.TrimSpace(ownerID) == "" {
		return nil, errors.New("SIP registration lease owner ID is required")
	}
	registrar, err := parseRegistrarURI(rc.Registrar)
	if err != nil {
		return nil, err
	}
	domain := rc.Domain
	if domain == "" {
		domain = registrar.Host
	}
	authUsername := rc.AuthUsername
	if authUsername == "" {
		authUsername = rc.Username
	}
	identity := strings.Join([]string{
		clusterID,
		strings.ToLower(registrar.String()),
		rc.Username,
		strings.ToLower(domain),
		authUsername,
	}, "\x00")
	digest := sha256.Sum256([]byte(identity))
	key := "abia:realtime:sip-registration:v1:" + hex.EncodeToString(digest[:])
	return &registrationOwner{
		log:       log.WithValues("registrationLeaseKey", hex.EncodeToString(digest[:8]), "nodeID", ownerID),
		store:     store,
		key:       key,
		ownerID:   ownerID,
		makeOwner: makeOwner,
		mon:       mon,
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}, nil
}

func (o *registrationOwner) Start() {
	o.startOnce.Do(func() { go o.run() })
}

func (o *registrationOwner) StopBefore(deadline time.Time) {
	o.stopOnce.Do(func() {
		o.mu.Lock()
		o.deadline = deadline
		o.mu.Unlock()
		close(o.stop)
	})
}

func (o *registrationOwner) WaitStopped() {
	<-o.done
}

func (o *registrationOwner) run() {
	defer close(o.done)
	for {
		select {
		case <-o.stop:
			return
		default:
		}

		token, err := newRegistrationLeaseToken()
		acquireAttempted := false
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), registrationLeaseRPCTimeout)
			var acquired bool
			acquireAttempted = true
			acquired, err = o.store.Acquire(ctx, o.key, token, registrationLeaseTTL)
			cancel()
			if err == nil && acquired {
				o.record("acquired")
				o.recordOwned(1)
				o.log.Infow("SIP registration ownership acquired", "owner", o.ownerID)
				if err = o.runOwned(token); err != nil && !errors.Is(err, errRegistrationLeaseLost) {
					o.log.Warnw("SIP registration ownership stopped", err, "owner", o.ownerID)
				}
				if o.stopping() {
					return
				}
				if !o.waitRetry(registrationLeaseRetry/2 + randomRegistrationDelay(registrationLeaseRetry/2)) {
					return
				}
				continue
			}
		}
		if err == nil {
			o.record("busy")
		} else if acquireAttempted {
			o.record("redis_error")
		} else {
			o.record("lease_error")
		}
		if err != nil {
			o.log.Warnw("SIP registration ownership unavailable; registration remains inactive", err, "owner", o.ownerID)
		}
		if !o.waitRetry(registrationLeaseRetry/2 + randomRegistrationDelay(registrationLeaseRetry/2)) {
			return
		}
	}
}

func (o *registrationOwner) runOwned(token string) error {
	defer o.recordOwned(-1)
	r, err := o.makeOwner()
	if err != nil {
		o.record("registrant_error")
		releaseErr := o.release(token)
		if releaseErr != nil {
			o.record("release_error")
		} else {
			o.record("released")
		}
		return errors.Join(fmt.Errorf("create SIP registration owner: %w", err), releaseErr)
	}
	r.Start()
	ticker := time.NewTicker(registrationLeaseRenewal)
	defer ticker.Stop()
	lastRenewal := time.Now()

	for {
		select {
		case <-o.stop:
			o.mu.Lock()
			deadline := o.deadline
			o.mu.Unlock()
			// A renewal may have failed transiently, or this process may have been
			// paused long enough for the lease to expire before shutdown. Confirm
			// and extend ownership before sending an un-REGISTER for the shared AOR.
			// If Redis cannot prove ownership, preserve the binding and let the TTL
			// expire; withdrawing it could erase a replacement owner's registration.
			owned := false
			var renewErr error
			if time.Until(deadline) > registrationLeaseRPCTimeout {
				ctx, cancel := context.WithTimeout(context.Background(), registrationLeaseRPCTimeout)
				owned, renewErr = o.store.Renew(ctx, o.key, token, registrationLeaseTTL)
				cancel()
			} else {
				renewErr = context.DeadlineExceeded
			}
			if renewErr != nil || !owned {
				if renewErr != nil {
					o.record("renewal_error")
				}
				o.record("lost")
				o.log.Errorw("SIP registration lease could not be confirmed before shutdown; preserving the binding until expiry",
					errors.Join(errRegistrationLeaseLost, renewErr), "owner", o.ownerID)
				r.StopWithoutUnregister()
				return errRegistrationLeaseLost
			}
			r.stopBefore(deadline)
			r.waitStopped()
			releaseErr := o.release(token)
			if releaseErr != nil {
				o.record("release_error")
			} else {
				o.record("released")
			}
			return releaseErr
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), registrationLeaseRPCTimeout)
			owned, renewErr := o.store.Renew(ctx, o.key, token, registrationLeaseTTL)
			cancel()
			if renewErr == nil && owned {
				lastRenewal = time.Now()
				continue
			}
			if renewErr != nil {
				o.record("renewal_error")
				o.log.Warnw("SIP registration lease renewal failed", renewErr, "owner", o.ownerID)
			}
			leaseLost := renewErr == nil && !owned
			leaseUncertain := renewErr != nil && time.Since(lastRenewal) >= registrationLeaseTTL/2
			if leaseLost || leaseUncertain {
				o.record("lost")
				o.log.Errorw("SIP registration lease lost; stopping refresh and preserving the binding until expiry", errRegistrationLeaseLost,
					"owner", o.ownerID)
				r.StopWithoutUnregister()
				// Redis ownership may still be valid after a renewal error. Let the
				// lease expire naturally instead of releasing it early: another node
				// must not start refreshing while this binding may still be alive.
				return errRegistrationLeaseLost
			}
		}
	}
}

func (o *registrationOwner) record(result string) {
	if o.mon != nil {
		o.mon.RegistrationLeaseEvent(result)
	}
}

func (o *registrationOwner) recordOwned(delta float64) {
	if o.mon != nil {
		o.mon.RegistrationLeaseOwned(delta)
	}
}

func (o *registrationOwner) release(token string) error {
	ctx, cancel := context.WithTimeout(context.Background(), registrationLeaseRPCTimeout)
	defer cancel()
	return o.store.Release(ctx, o.key, token)
}

func (o *registrationOwner) waitRetry(delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-o.stop:
		return false
	case <-timer.C:
		return true
	}
}

func (o *registrationOwner) stopping() bool {
	select {
	case <-o.stop:
		return true
	default:
		return false
	}
}

func newRegistrationLeaseToken() (string, error) {
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(token[:]), nil
}
