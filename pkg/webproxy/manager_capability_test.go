package webproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestManagerCapabilityPrefixCollision(t *testing.T) {
	t.Parallel()

	profiles := testProfiles(t)
	// Force two distinct credentials to share a prefix without searching for
	// an HMAC collision. A prefix match alone must never authorize a profile.
	copy(profiles[1].capability[:8], profiles[0].capability[:8])
	manager := testManager(t, profiles, nil, nil)
	for _, profile := range profiles {
		t.Run(profile.Mode().String(), func(t *testing.T) {
			t.Parallel()
			matched, ok := manager.MatchCapability(profile.Capability())
			if !ok || matched != profile {
				t.Fatal("did not return the profile for the complete credential")
			}
			created := createTestSession(t, manager, profile)
			if created.Session.Profile() != profile {
				t.Fatal("bootstrap authenticated the wrong profile")
			}
		})
	}
	for index := range len(Capability{}) {
		t.Run(fmt.Sprintf("changed-byte-%d", index), func(t *testing.T) {
			t.Parallel()
			unknown := profiles[0].Capability()
			unknown[index] ^= 0xff
			matched, ok := manager.MatchCapability(unknown)
			if ok || matched != (Profile{}) {
				t.Fatal("accepted an incomplete credential match")
			}
			if token, err := manager.IssueBootstrap(unknown, "192.0.2.1"); token != "" || !errors.Is(err, ErrAuthentication) {
				t.Fatalf("invalid credential issued a bootstrap: %v", err)
			}
		})
	}
}

func TestManagerCapabilityOwnsProfiles(t *testing.T) {
	t.Parallel()

	profiles := testProfiles(t)
	original := profiles[0]
	manager := testManager(t, profiles, nil, nil)
	profiles[0].capability[0] ^= 0xff
	profiles[0].name = "changed"

	matched, ok := manager.MatchCapability(original.Capability())
	if !ok || matched != original {
		t.Fatal("caller mutation changed the manager's credentials")
	}
	if _, ok := manager.MatchCapability(profiles[0].Capability()); ok {
		t.Fatal("caller mutation authorized a new credential")
	}
}

func BenchmarkManagerMatchCapability(b *testing.B) {
	for _, count := range []int{2, 64, 1024} {
		b.Run(fmt.Sprintf("profiles-%d", count), func(b *testing.B) {
			profiles := make([]Profile, count)
			for i := range profiles {
				// Distinct synthetic prefixes keep the hit and miss cases exact.
				binary.LittleEndian.PutUint64(profiles[i].capability[:8], uint64(i+1))
			}
			manager, err := NewManager(DefaultManagerConfig(profiles, "127.0.0.1:443"))
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if err := manager.Shutdown(ctx); err != nil {
					b.Errorf("Shutdown: %v", err)
				}
			})
			valid := profiles[len(profiles)-1].Capability()
			prefixHit := valid
			prefixHit[len(prefixHit)-1] ^= 0xff
			for _, test := range []struct {
				name       string
				capability Capability
				matched    bool
			}{
				{name: "unknown-prefix"},
				{name: "known-prefix-invalid", capability: prefixHit},
				{name: "valid", capability: valid, matched: true},
			} {
				b.Run(test.name, func(b *testing.B) {
					b.ReportAllocs()
					for b.Loop() {
						if _, ok := manager.MatchCapability(test.capability); ok != test.matched {
							b.Fatal("unexpected capability match")
						}
					}
				})
			}
		})
	}
}
