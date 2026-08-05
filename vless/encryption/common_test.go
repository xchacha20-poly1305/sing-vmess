package encryption

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"

	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

func newConnPair(t *testing.T, useAES bool) (client, server *CommonConn) {
	t.Helper()
	clientPipe, serverPipe := net.Pipe()
	t.Cleanup(func() {
		clientPipe.Close()
		serverPipe.Close()
	})
	unitedKey := make([]byte, 32)
	if _, err := rand.Read(unitedKey); err != nil {
		t.Fatal(err)
	}
	client = NewCommonConn(clientPipe, useAES)
	server = NewCommonConn(serverPipe, useAES)
	for _, conn := range []*CommonConn{client, server} {
		conn.unitedKey = unitedKey
	}
	client.aead = NewAEAD([]byte("c2s"), unitedKey, useAES)
	server.peerAEAD = NewAEAD([]byte("c2s"), unitedKey, useAES)
	server.aead = NewAEAD([]byte("s2c"), unitedKey, useAES)
	client.peerAEAD = NewAEAD([]byte("s2c"), unitedKey, useAES)
	return
}

func randomBytes(t *testing.T, size int) []byte {
	t.Helper()
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	return data
}

// sendBuffer writes payload as a buffer carrying the headroom advertised by
// the connection, which is what bufio.Copy hands over.
func sendBuffer(conn *CommonConn, payload []byte) error {
	buffer := buf.NewSize(conn.FrontHeadroom() + len(payload) + conn.RearHeadroom())
	buffer.Resize(conn.FrontHeadroom(), 0)
	buffer.Reserve(conn.RearHeadroom())
	buffer.Write(payload)
	buffer.OverCap(conn.RearHeadroom())
	return conn.WriteBuffer(buffer)
}

func TestExtendedConn(t *testing.T) {
	t.Parallel()
	for _, useAES := range []bool{true, false} {
		for _, size := range []int{1, 1024, XrayBufferSize, XrayBufferSize + 1, 60 * 1024} {
			payload := randomBytes(t, size)
			t.Run("", func(t *testing.T) {
				client, server := newConnPair(t, useAES)
				errChan := make(chan error, 1)
				go func() {
					errChan <- sendBuffer(client, payload)
				}()
				received := make([]byte, 0, size)
				for len(received) < size {
					buffer := buf.NewSize(XrayBufferSize + client.FrontHeadroom() + client.RearHeadroom())
					if err := server.ReadBuffer(buffer); err != nil {
						t.Fatal(err)
					}
					received = append(received, buffer.Bytes()...)
					buffer.Release()
				}
				if err := <-errChan; err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(received, payload) {
					t.Fatal("payload mismatch")
				}
			})
		}
	}
}

// TestExtendedConnCompatibility checks that the buffered and the plain paths
// produce and consume the same stream, in both directions.
func TestExtendedConnCompatibility(t *testing.T) {
	t.Parallel()
	payload := randomBytes(t, 40*1024)
	for _, useAES := range []bool{true, false} {
		t.Run("write_buffer_read_plain", func(t *testing.T) {
			client, server := newConnPair(t, useAES)
			go sendBuffer(client, payload)
			received := make([]byte, len(payload))
			if _, err := io.ReadFull(server, received); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(received, payload) {
				t.Fatal("payload mismatch")
			}
		})
		t.Run("write_plain_read_buffer", func(t *testing.T) {
			client, server := newConnPair(t, useAES)
			go client.Write(payload)
			received := make([]byte, 0, len(payload))
			for len(received) < len(payload) {
				buffer := buf.NewSize(1024) // smaller than a record, exercises the input cache
				if err := server.ReadBuffer(buffer); err != nil {
					t.Fatal(err)
				}
				received = append(received, buffer.Bytes()...)
				buffer.Release()
			}
			if !bytes.Equal(received, payload) {
				t.Fatal("payload mismatch")
			}
		})
		t.Run("write_buffer_without_headroom", func(t *testing.T) {
			client, server := newConnPair(t, useAES)
			go func() {
				buffer := buf.NewSize(len(payload))
				buffer.Write(payload)
				client.WriteBuffer(buffer)
			}()
			received := make([]byte, len(payload))
			if _, err := io.ReadFull(server, received); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(received, payload) {
				t.Fatal("payload mismatch")
			}
		})
	}
}

func TestHeadroom(t *testing.T) {
	t.Parallel()
	conn := NewCommonConn(nil, true)
	if headroom := N.CalculateFrontHeadroom(conn); headroom != HeaderLength {
		t.Fatal("unexpected front headroom: ", headroom)
	}
	if headroom := N.CalculateRearHeadroom(conn); headroom != AEADTagLength {
		t.Fatal("unexpected rear headroom: ", headroom)
	}
}
