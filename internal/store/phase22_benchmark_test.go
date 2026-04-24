package store

import "testing"

// Phase 22 C.5: per-DM DB cache benchmarks.
func BenchmarkDMDB_CacheHit(b *testing.B) {
	s, cleanup := makeBenchmarkStore(b)
	defer cleanup()

	dm, err := s.CreateOrGetDirectMessage(GenerateID("dm_"), "usr_a", "usr_b")
	if err != nil {
		b.Fatalf("CreateOrGetDirectMessage: %v", err)
	}
	if _, err := s.DMDB(dm.ID); err != nil {
		b.Fatalf("prime DMDB cache: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := s.DMDB(dm.ID); err != nil {
			b.Fatalf("DMDB: %v", err)
		}
	}
}

func BenchmarkDMDB_CacheMiss(b *testing.B) {
	s, cleanup := makeBenchmarkStore(b)
	defer cleanup()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		id := GenerateID("dm_")
		dm, err := s.CreateOrGetDirectMessage(id, "usr_a", "usr_b")
		if err != nil {
			b.Fatalf("CreateOrGetDirectMessage: %v", err)
		}
		if _, err := s.DMDB(dm.ID); err != nil {
			b.Fatalf("DMDB: %v", err)
		}
	}
}

func makeBenchmarkStore(tb testing.TB) (*Store, func()) {
	tb.Helper()
	dataDir := tb.TempDir()
	s, err := Open(dataDir)
	if err != nil {
		tb.Fatalf("Open: %v", err)
	}
	cleanup := func() { _ = s.Close() }
	return s, cleanup
}
