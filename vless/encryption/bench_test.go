package encryption

import (
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/bufio"
)

// benchConn is a net.Conn that discards everything written to it and replays a
// fixed byte slice on read, so that benchmarks only measure the work done by
// CommonConn itself.
type benchConn struct {
	source []byte
}

func (c *benchConn) Read(b []byte) (int, error) {
	if len(c.source) == 0 {
		return 0, io.EOF
	}
	n := copy(b, c.source)
	c.source = c.source[n:]
	return n, nil
}

func (c *benchConn) Write(b []byte) (int, error)        { return len(b), nil }
func (c *benchConn) Close() error                       { return nil }
func (c *benchConn) LocalAddr() net.Addr                { return nil }
func (c *benchConn) RemoteAddr() net.Addr               { return nil }
func (c *benchConn) SetDeadline(t time.Time) error      { return nil }
func (c *benchConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *benchConn) SetWriteDeadline(t time.Time) error { return nil }

// netConnOnly hides everything but net.Conn, reproducing how bufio.Copy had to
// treat CommonConn before it implemented N.ExtendedConn.
type netConnOnly struct {
	net.Conn
}

// countingReader feeds bufio.Copy with a fixed amount of data.
type countingReader struct {
	data      []byte
	remaining int
}

func (r *countingReader) Read(b []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	n := copy(b, r.data)
	if n > r.remaining {
		n = r.remaining
	}
	r.remaining -= n
	return n, nil
}

type discardWriter struct{}

func (discardWriter) Write(b []byte) (int, error) { return len(b), nil }

func newBenchConn(tb testing.TB, useAES bool, conn net.Conn) *CommonConn {
	tb.Helper()
	unitedKey := make([]byte, 32)
	if _, err := rand.Read(unitedKey); err != nil {
		tb.Fatal(err)
	}
	commonConn := NewCommonConn(conn, useAES)
	commonConn.unitedKey = unitedKey
	commonConn.aead = NewAEAD([]byte("bench-out"), unitedKey, useAES)
	commonConn.peerAEAD = NewAEAD([]byte("bench-in"), unitedKey, useAES)
	return commonConn
}

const benchStreamSize = 4 << 20

func benchmarkWrite(b *testing.B, useAES, extended bool) {
	source := make([]byte, 64*1024)
	if _, err := rand.Read(source); err != nil {
		b.Fatal(err)
	}
	conn := newBenchConn(b, useAES, &benchConn{})
	var destination io.Writer = conn
	if !extended {
		destination = netConnOnly{conn}
	}
	b.SetBytes(benchStreamSize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := bufio.Copy(destination, &countingReader{data: source, remaining: benchStreamSize})
		if err != nil {
			b.Fatal(err)
		}
	}
}

// benchStream returns benchStreamSize bytes of plaintext encoded into records
// by a CommonConn, together with the key material needed to read it back.
func benchStream(b *testing.B, useAES bool) (stream []byte, unitedKey []byte) {
	b.Helper()
	unitedKey = make([]byte, 32)
	if _, err := rand.Read(unitedKey); err != nil {
		b.Fatal(err)
	}
	payload := make([]byte, 64*1024)
	if _, err := rand.Read(payload); err != nil {
		b.Fatal(err)
	}
	collector := &collectConn{}
	writer := NewCommonConn(collector, useAES)
	writer.unitedKey = unitedKey
	writer.aead = NewAEAD([]byte("bench-stream"), unitedKey, useAES)
	for written := 0; written < benchStreamSize; {
		next := min(len(payload), benchStreamSize-written)
		if _, err := writer.Write(payload[:next]); err != nil {
			b.Fatal(err)
		}
		written += next
	}
	return collector.data, unitedKey
}

type collectConn struct {
	benchConn
	data []byte
}

func (c *collectConn) Write(b []byte) (int, error) {
	c.data = append(c.data, b...)
	return len(b), nil
}

func benchmarkRead(b *testing.B, useAES, extended bool) {
	stream, unitedKey := benchStream(b, useAES)
	b.SetBytes(benchStreamSize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		conn := NewCommonConn(&benchConn{source: stream}, useAES)
		conn.unitedKey = unitedKey
		conn.peerAEAD = NewAEAD([]byte("bench-stream"), unitedKey, useAES)
		var source io.Reader = conn
		if !extended {
			source = netConnOnly{conn}
		}
		b.StartTimer()
		n, err := bufio.Copy(discardWriter{}, source)
		if err != nil {
			b.Fatal(err)
		}
		if n != benchStreamSize {
			b.Fatalf("copied %d, want %d", n, benchStreamSize)
		}
	}
}

func BenchmarkCopyWriteAESLegacy(b *testing.B)    { benchmarkWrite(b, true, false) }
func BenchmarkCopyWriteAESExtended(b *testing.B)  { benchmarkWrite(b, true, true) }
func BenchmarkCopyWriteChaChaLegacy(b *testing.B) { benchmarkWrite(b, false, false) }
func BenchmarkCopyWriteChaChaExtended(b *testing.B) {
	benchmarkWrite(b, false, true)
}

func BenchmarkCopyReadAESLegacy(b *testing.B)      { benchmarkRead(b, true, false) }
func BenchmarkCopyReadAESExtended(b *testing.B)    { benchmarkRead(b, true, true) }
func BenchmarkCopyReadChaChaLegacy(b *testing.B)   { benchmarkRead(b, false, false) }
func BenchmarkCopyReadChaChaExtended(b *testing.B) { benchmarkRead(b, false, true) }
