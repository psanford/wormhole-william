package wormhole

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"io/ioutil"
	"net"
	"sync"
	"testing"

	"github.com/psanford/wormhole-william/rendezvous/rendezvousservertest"
)

func TestWormholeFileTransportSendRecvDirect(t *testing.T) {
	ctx := context.Background()

	rs := rendezvousservertest.NewServer()
	defer rs.Close()

	url := rs.WebSocketURL()

	// disable transit relay for this test
	DefaultTransitRelayAddress = ""

	var c0 Client
	c0.RendezvousURL = url

	var c1 Client
	c1.RendezvousURL = url

	fileContent := make([]byte, 1<<16)
	for i := 0; i < len(fileContent); i++ {
		fileContent[i] = byte(i)
	}

	buf := bytes.NewReader(fileContent)

	code, resultCh, err := c0.SendFile(ctx, "file.txt", buf)
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := c1.Receive(ctx, code)
	if err != nil {
		t.Fatal(err)
	}

	got, err := ioutil.ReadAll(receiver)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, fileContent) {
		t.Fatalf("File contents mismatch")
	}

	result := <-resultCh
	if !result.OK {
		t.Fatalf("Expected ok result but got: %+v", result)
	}
}

func TestWormholeFileTransportSendRecvViaRelayServer(t *testing.T) {
	ctx := context.Background()

	rs := rendezvousservertest.NewServer()
	defer rs.Close()

	url := rs.WebSocketURL()

	testDisableLocalListener = true
	defer func() { testDisableLocalListener = false }()

	relayServer := newTestRelayServer()
	defer relayServer.close()

	var c0 Client
	c0.RendezvousURL = url
	c0.TransitRelayAddress = relayServer.addr

	var c1 Client
	c1.RendezvousURL = url
	c1.TransitRelayAddress = relayServer.addr

	fileContent := make([]byte, 1<<16)
	for i := 0; i < len(fileContent); i++ {
		fileContent[i] = byte(i)
	}

	buf := bytes.NewReader(fileContent)

	code, resultCh, err := c0.SendFile(ctx, "file.txt", buf)
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := c1.Receive(ctx, code)
	if err != nil {
		t.Fatal(err)
	}

	got, err := ioutil.ReadAll(receiver)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, fileContent) {
		t.Fatalf("File contents mismatch")
	}

	result := <-resultCh
	if !result.OK {
		t.Fatalf("Expected ok result but got: %+v", result)
	}
}

func TestWormholeDirectoryTransportSendRecvDirect(t *testing.T) {
	ctx := context.Background()

	rs := rendezvousservertest.NewServer()
	defer rs.Close()

	url := rs.WebSocketURL()

	// disable transit relay for this test
	DefaultTransitRelayAddress = ""

	var c0 Client
	c0.RendezvousURL = url

	var c1 Client
	c1.RendezvousURL = url

	personalizeContent := make([]byte, 1<<16)
	for i := 0; i < len(personalizeContent); i++ {
		personalizeContent[i] = byte(i)
	}

	bodiceContent := []byte("placarding-whereat")

	entries := []DirectoryEntry{
		{
			Path: "skyjacking/personalize.txt",
			Reader: func() (io.ReadCloser, error) {
				b := bytes.NewReader(personalizeContent)
				return ioutil.NopCloser(b), nil
			},
		},
		{
			Path: "skyjacking/bodice-Maytag.txt",
			Reader: func() (io.ReadCloser, error) {
				b := bytes.NewReader(bodiceContent)
				return ioutil.NopCloser(b), nil
			},
		},
	}

	code, resultCh, err := c0.SendDirectory(ctx, "skyjacking", entries)
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := c1.Receive(ctx, code)
	if err != nil {
		t.Fatal(err)
	}

	got, err := ioutil.ReadAll(receiver)
	if err != nil {
		t.Fatal(err)
	}

	r, err := zip.NewReader(bytes.NewReader(got), int64(len(got)))
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range r.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		body, err := ioutil.ReadAll(rc)
		if err != nil {
			t.Fatal(err)
		}
		rc.Close()

		if f.Name == "personalize.txt" {
			if !bytes.Equal(body, personalizeContent) {
				t.Fatal("personalize.txt file content does not match")
			}
		} else if f.Name == "bodice-Maytag.txt" {
			if !bytes.Equal(bodiceContent, body) {
				t.Fatalf("bodice-Maytag.txt file content does not match %s vs %s", bodiceContent, body)
			}
		} else {
			t.Fatalf("Unexpected file %s", f.Name)
		}
	}

	result := <-resultCh
	if !result.OK {
		t.Fatalf("Expected ok result but got: %+v", result)
	}
}

type testRelayServer struct {
	l       net.Listener
	addr    string
	wg      sync.WaitGroup
	mu      sync.Mutex
	streams map[string]net.Conn
}

func newTestRelayServer() *testRelayServer {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		panic(err)
	}

	rs := &testRelayServer{
		l:       l,
		addr:    l.Addr().String(),
		streams: make(map[string]net.Conn),
	}

	go rs.run()
	return rs
}

func (ts *testRelayServer) close() {
	ts.l.Close()
	ts.wg.Wait()
}

func (ts *testRelayServer) run() {
	for {
		conn, err := ts.l.Accept()
		if err != nil {
			return
		}

		ts.wg.Add(1)
		go ts.handleConn(conn)
	}
}

var headerPrefix = []byte("please relay ")
var headerSide = []byte(" for side ")

func (ts *testRelayServer) handleConn(c net.Conn) {
	// requests look like:
	// "please relay 10bf5ab71e48a3ca74b0a0d4d54f66f38704a76d15885442a8df141680fd for side 4a74cb8a377c970a\n"

	defer ts.wg.Done()
	headerBuf := make([]byte, 64)

	matchExpect := func(expect []byte) bool {
		got := headerBuf[:len(expect)]
		_, err := io.ReadFull(c, got)
		if err != nil {
			c.Close()
			return false
		}

		if !bytes.Equal(got, expect) {
			c.Write([]byte("bad handshake\n"))
			c.Close()
			return false
		}

		return true
	}

	isHex := func(str string) bool {
		_, err := hex.DecodeString(str)
		if err != nil {
			c.Write([]byte("bad handshake\n"))
			c.Close()
			return false
		}
		return true
	}

	if !matchExpect(headerPrefix) {
		return
	}

	_, err := io.ReadFull(c, headerBuf)
	if err != nil {
		c.Close()
		return
	}

	chanID := string(headerBuf)
	if !isHex(chanID) {
		return
	}

	if !matchExpect(headerSide) {
		return
	}

	sideBuf := headerBuf[:16]
	_, err = io.ReadFull(c, sideBuf)
	if err != nil {
		c.Close()
		return
	}

	side := string(sideBuf)
	if !isHex(side) {
		return
	}

	// read \n
	_, err = io.ReadFull(c, headerBuf[:1])
	if err != nil {
		c.Close()
		return
	}

	ts.mu.Lock()
	existing, found := ts.streams[chanID]
	if !found {
		ts.streams[chanID] = c
	}
	ts.mu.Unlock()

	if found {
		existing.Write([]byte("ok\n"))
		c.Write([]byte("ok\n"))
		go func() {
			io.Copy(c, existing)
			existing.Close()
			c.Close()

		}()

		io.Copy(existing, c)
		c.Close()
		existing.Close()
	}
}
