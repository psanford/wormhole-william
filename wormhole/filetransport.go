package wormhole

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"math/big"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/psanford/wormhole-william/random"
	"github.com/psanford/wormhole-william/rendezvous"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/secretbox"
)

type FileReceiver struct {
	Name      string
	Type      FileType
	Bytes     int
	FileCount int

	cryptor   *transportCryptor
	buf       []byte
	readCount int
	sha256    hash.Hash

	readErr error
}

type finalAck struct {
	Ack    string `json:"ack"`
	SHA256 string `json:"sha256"`
}

func (f *FileReceiver) Read(p []byte) (int, error) {
	if f.readErr != nil {
		return 0, f.readErr
	}

	if len(f.buf) == 0 {
		rec, err := f.cryptor.readRecord()
		if err != nil {
			f.readErr = err
			return 0, err
		}
		f.buf = rec
	}

	n := copy(p, f.buf)
	f.buf = f.buf[n:]
	f.readCount += n
	f.sha256.Write(p[:n])
	if f.readCount >= f.Bytes {
		f.readErr = io.EOF

		sum := f.sha256.Sum(nil)
		ack := finalAck{
			Ack:    "ok",
			SHA256: fmt.Sprintf("%x", sum),
		}

		msg, _ := json.Marshal(ack)
		f.cryptor.writeRecord(msg)
		f.cryptor.Close()
	}

	return n, nil
}

type FileType int

const (
	FileTypeFile FileType = iota + 1
	FileTypeDirectory
)

func (c *Client) RecvFile(ctx context.Context, code string) (fileReciever *FileReceiver, returnErr error) {

	sideID := random.SideID()
	appID := c.appID()
	rc := rendezvous.NewClient(c.url(), sideID, appID)

	defer func() {
		mood := rendezvous.Errory
		if returnErr == nil {
			mood = rendezvous.Happy
		} else if returnErr == errDecryptFailed {
			mood = rendezvous.Scary
		}
		rc.Close(ctx, mood)
	}()

	_, err := rc.Connect(ctx)
	if err != nil {
		return nil, err
	}
	nameplate := strings.SplitN(code, "-", 2)[0]

	err = rc.AttachMailbox(ctx, nameplate)
	if err != nil {
		return nil, err
	}

	clientProto := newClientProtocol(ctx, rc, sideID, appID)

	err = clientProto.WritePake(ctx, code)
	if err != nil {
		return nil, err
	}

	err = clientProto.ReadPake()
	if err != nil {
		return nil, err
	}

	err = clientProto.WriteVersion(ctx)
	if err != nil {
		return nil, err
	}

	_, err = clientProto.ReadVersion()
	if err != nil {
		return nil, err
	}

	collector, err := clientProto.Collect(collectOffer, collectTransit)
	if err != nil {
		return nil, err
	}

	var fr FileReceiver

	if collector.offer.File != nil {
		fr.Type = FileTypeFile
		fr.Name = collector.offer.File.FileName
		fr.Bytes = int(collector.offer.File.FileSize)
		fr.FileCount = 1
	} else if collector.offer.Directory != nil {
		fr.Type = FileTypeDirectory
		fr.Name = collector.offer.Directory.Dirname
		fr.Bytes = int(collector.offer.Directory.ZipSize)
		fr.FileCount = int(collector.offer.Directory.NumFiles)
	} else {
		return nil, errors.New("Got non-file transfer offer")
	}
	transitKey := deriveTransitKey(clientProto.sharedKey, appID)
	transport := newFileTransport(transitKey, appID)
	err = transport.listen()
	if err != nil {
		return nil, err
	}

	transitMsg, err := transport.makeTransitMsg()
	if err != nil {
		return nil, fmt.Errorf("Make transit msg error: %s", err)
	}

	err = clientProto.WriteAppData(ctx, transitMsg)
	if err != nil {
		return nil, err
	}

	answer := genericMessage{
		Answer: &answerMsg{
			FileAck: "ok",
		},
	}

	err = clientProto.WriteAppData(ctx, answer)
	if err != nil {
		return nil, err
	}

	conn, err := transport.connectDirect(collector.transit)
	if err != nil {
		return nil, err
	}

	if conn == nil {
		conn, err = transport.connectViaRelay(collector.transit)
		if err != nil {
			return nil, err
		}
	}

	if conn == nil {
		return nil, errors.New("Failed to establish connection")
	}

	cryptor := newTransportCryptor(conn, transitKey, "transit_record_sender_key", "transit_record_receiver_key")

	fr.cryptor = cryptor
	fr.sha256 = sha256.New()

	return &fr, nil
}

type transportCryptor struct {
	conn           net.Conn
	prefixBuf      []byte
	nextReadNonce  *big.Int
	nextWriteNonce uint64
	err            error
	readKey        [32]byte
	writeKey       [32]byte
}

func newTransportCryptor(c net.Conn, transitKey []byte, readPurpose, writePurpose string) *transportCryptor {
	r := hkdf.New(sha256.New, transitKey, nil, []byte(readPurpose))
	var readKey [32]byte
	_, err := io.ReadFull(r, readKey[:])
	if err != nil {
		panic(err)
	}

	r = hkdf.New(sha256.New, transitKey, nil, []byte(writePurpose))
	var writeKey [32]byte
	_, err = io.ReadFull(r, writeKey[:])
	if err != nil {
		panic(err)
	}

	return &transportCryptor{
		conn:          c,
		prefixBuf:     make([]byte, 4+random.NonceSize),
		nextReadNonce: big.NewInt(0),
		readKey:       readKey,
		writeKey:      writeKey,
	}
}
func (d *transportCryptor) Close() error {
	return d.conn.Close()
}

func (d *transportCryptor) readRecord() ([]byte, error) {
	if d.err != nil {
		return nil, d.err
	}
	_, err := io.ReadFull(d.conn, d.prefixBuf)
	if err != nil {
		d.err = err
		return nil, d.err
	}

	l := binary.BigEndian.Uint32(d.prefixBuf[:4])
	var nonce [24]byte
	copy(nonce[:], d.prefixBuf[4:])

	var bigNonce big.Int
	bigNonce.SetBytes(nonce[:])

	if bigNonce.Cmp(d.nextReadNonce) != 0 {
		d.err = errors.New("Recieved out-of-order record")
		return nil, d.err
	}

	d.nextReadNonce.Add(d.nextReadNonce, big.NewInt(1))

	sealedMsg := make([]byte, l-random.NonceSize)
	_, err = io.ReadFull(d.conn, sealedMsg)
	if err != nil {
		d.err = err
		return nil, d.err
	}

	out, ok := secretbox.Open(nil, sealedMsg, &nonce, &d.readKey)
	if !ok {
		d.err = errDecryptFailed
		return nil, d.err
	}

	return out, nil
}

func (d *transportCryptor) writeRecord(msg []byte) error {
	var nonce [random.NonceSize]byte

	if d.nextWriteNonce == math.MaxUint64 {
		panic("Nonce exhaustion")
	}

	binary.BigEndian.PutUint64(nonce[random.NonceSize-8:], d.nextWriteNonce)
	d.nextWriteNonce++

	sealedMsg := secretbox.Seal(nil, msg, &nonce, &d.writeKey)

	nonceAndSealedMsg := append(nonce[:], sealedMsg...)

	if len(nonceAndSealedMsg) >= math.MaxUint32 {
		panic(fmt.Sprintf("writeRecord too large: %d", len(nonceAndSealedMsg)))
	}

	l := make([]byte, 4)
	binary.BigEndian.PutUint32(l, uint32(len(nonceAndSealedMsg)))

	lenNonceAndSealedMsg := append(l, nonceAndSealedMsg...)

	_, err := d.conn.Write(lenNonceAndSealedMsg)
	return err
}

func newFileTransport(transitKey []byte, appID string) *fileTransport {
	return &fileTransport{
		transitKey: transitKey,
		appID:      appID,
	}
}

type fileTransport struct {
	listener   net.Listener
	transitKey []byte
	appID      string
}

func (t *fileTransport) connectViaRelay(otherTransit *transitMsg) (net.Conn, error) {
	cancelFuncs := make(map[string]func())

	successChan := make(chan net.Conn)
	failChan := make(chan string)

	var count int

	for _, outerHint := range otherTransit.HintsV1 {
		if outerHint.Type == "relay-v1" {
			for _, innerHint := range outerHint.Hints {
				if innerHint.Type == "direct-tcp-v1" {
					count++
					ctx, cancel := context.WithCancel(context.Background())
					addr := net.JoinHostPort(innerHint.Hostname, strconv.Itoa(innerHint.Port))

					cancelFuncs[addr] = cancel

					go t.connectToRelay(ctx, addr, successChan, failChan)
				}
			}
		}
	}

	var conn net.Conn

	connectTimeout := time.After(5 * time.Second)

	for i := 0; i < count; i++ {
		select {
		case <-failChan:
		case conn = <-successChan:
		case <-connectTimeout:
			for _, cancel := range cancelFuncs {
				cancel()
			}
		}
	}

	return conn, nil
}

func (t *fileTransport) connectDirect(otherTransit *transitMsg) (net.Conn, error) {
	cancelFuncs := make(map[string]func())

	successChan := make(chan net.Conn)
	failChan := make(chan string)

	var count int

	for _, hint := range otherTransit.HintsV1 {
		if hint.Type == "direct-tcp-v1" {
			count++
			ctx, cancel := context.WithCancel(context.Background())
			addr := net.JoinHostPort(hint.Hostname, strconv.Itoa(hint.Port))

			cancelFuncs[addr] = cancel

			go t.connectToSingleHost(ctx, addr, successChan, failChan)
		}
	}

	var conn net.Conn

	connectTimeout := time.After(5 * time.Second)

	for i := 0; i < count; i++ {
		select {
		case <-failChan:
		case conn = <-successChan:
		case <-connectTimeout:
			for _, cancel := range cancelFuncs {
				cancel()
			}
		}
	}

	return conn, nil
}

func (t *fileTransport) connectToRelay(ctx context.Context, addr string, successChan chan net.Conn, failChan chan string) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		failChan <- addr
		return
	}

	_, err = conn.Write(t.relayHandshakeHeader())
	if err != nil {
		failChan <- addr
		return
	}

	gotOk := make([]byte, 3)
	_, err = io.ReadFull(conn, gotOk)
	if err != nil {
		conn.Close()
		failChan <- addr
		return
	}

	if !bytes.Equal(gotOk, []byte("ok\n")) {
		conn.Close()
		failChan <- addr
		return
	}

	t.directHandshake(ctx, addr, conn, successChan, failChan)
}

func (t *fileTransport) connectToSingleHost(ctx context.Context, addr string, successChan chan net.Conn, failChan chan string) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)

	if err != nil {
		failChan <- addr
		return
	}

	t.directHandshake(ctx, addr, conn, successChan, failChan)
}

func (t *fileTransport) directHandshake(ctx context.Context, addr string, conn net.Conn, successChan chan net.Conn, failChan chan string) {
	expectHeader := t.senderHandshakeHeader()

	gotHeader := make([]byte, len(expectHeader))

	_, err := io.ReadFull(conn, gotHeader)
	if err != nil {
		conn.Close()
		failChan <- addr
		return
	}

	if subtle.ConstantTimeCompare(gotHeader, expectHeader) != 1 {
		conn.Close()
		failChan <- addr
		return
	}

	_, err = conn.Write(t.receiverHandshakeHeader())
	if err != nil {
		conn.Close()
		failChan <- addr
		return
	}

	gotOk := make([]byte, 3)
	_, err = io.ReadFull(conn, gotOk)
	if err != nil {
		conn.Close()
		failChan <- addr
		return
	}

	if !bytes.Equal(gotOk, []byte("go\n")) {
		conn.Close()
		failChan <- addr
		return
	}

	successChan <- conn
}

func (t *fileTransport) makeTransitMsg() (*transitMsg, error) {
	_, portStr, err := net.SplitHostPort(t.listener.Addr().String())
	if err != nil {
		return nil, err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("Port isn't an integer? %s", portStr)
	}

	addrs := nonLocalhostAddresses()

	msg := transitMsg{
		AbilitiesV1: []transitAbility{
			{
				Type: "direct-tcp-v1",
			},
			{
				Type: "relay-v1",
			},
		},
	}

	for _, addr := range addrs {
		msg.HintsV1 = append(msg.HintsV1, transitHintsV1{
			Type:     "direct-tcp-v1",
			Priority: 0.0,
			Hostname: addr,
			Port:     port,
		})
	}

	return &msg, nil
}

func (t *fileTransport) senderHandshakeHeader() []byte {
	purpose := "transit_sender"

	r := hkdf.New(sha256.New, t.transitKey, nil, []byte(purpose))
	out := make([]byte, 32)

	_, err := io.ReadFull(r, out)
	if err != nil {
		panic(err)
	}

	return []byte(fmt.Sprintf("transit sender %x ready\n\n", out))
}

func (t *fileTransport) relayHandshakeHeader() []byte {
	purpose := "transit_relay_token"

	r := hkdf.New(sha256.New, t.transitKey, nil, []byte(purpose))
	out := make([]byte, 32)

	_, err := io.ReadFull(r, out)
	if err != nil {
		panic(err)
	}

	sideID := random.Hex(8)

	return []byte(fmt.Sprintf("please relay %x for side %s\n", out, sideID))
}

func (t *fileTransport) receiverHandshakeHeader() []byte {
	purpose := "transit_receiver"

	r := hkdf.New(sha256.New, t.transitKey, nil, []byte(purpose))
	out := make([]byte, 32)

	_, err := io.ReadFull(r, out)
	if err != nil {
		panic(err)
	}

	return []byte(fmt.Sprintf("transit receiver %x ready\n\n", out))
}

func (t *fileTransport) listen() error {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return err
	}

	t.listener = l
	return nil
}

func nonLocalhostAddresses() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}

	var outAddrs []string

	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				outAddrs = append(outAddrs, ipnet.IP.String())
			}
		}
	}

	return outAddrs
}
