package byteslice

// Telego local modification: respect sync.Pool's permitted buffer discard.
// The pool implementation and benchmarks retain their upstream behavior.

import "testing"

func TestByteSlice(t *testing.T) {
	buf := Get(8)
	if len(buf) != 8 || cap(buf) != 8 {
		t.Fatalf("Get(8): len=%d cap=%d, want 8 and 8", len(buf), cap(buf))
	}
	copy(buf, "ff")
	if string(buf[:2]) != "ff" {
		t.Fatal("expect copy result is ff, but not")
	}

	Put(buf)

	newBuf := Get(7)
	defer Put(newBuf)
	if len(newBuf) != 7 || cap(newBuf) != 8 {
		t.Fatalf("Get(7): len=%d cap=%d, want 7 and 8", len(newBuf), cap(newBuf))
	}
	// sync.Pool can discard entries even without a garbage collection.
	if &newBuf[0] == &buf[0] && string(newBuf[:2]) != "ff" {
		t.Fatal("reused array did not preserve its contents")
	}

	otherBuf := Get(7)
	defer Put(otherBuf)
	if len(otherBuf) != 7 || cap(otherBuf) != 8 {
		t.Fatalf("second Get(7): len=%d cap=%d, want 7 and 8", len(otherBuf), cap(otherBuf))
	}
	if &otherBuf[0] == &newBuf[0] {
		t.Fatal("simultaneously held slices share the same array")
	}
}

func BenchmarkByteSlice(b *testing.B) {
	b.Run("Run.N", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			bs := Get(1024)
			Put(bs)
		}
	})
	b.Run("Run.Parallel", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				bs := Get(1024)
				Put(bs)
			}
		})
	})
}
