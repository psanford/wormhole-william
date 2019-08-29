package wormhole

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"strings"

	"github.com/psanford/wormhole-william/random"
	"github.com/psanford/wormhole-william/rendezvous"
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

func (f *FileReceiver) Read(p []byte) (int, error) {
	if f.readErr != nil {
		return 0, f.readErr
	}

	if len(f.buf) == 0 {
		rec, err := f.cryptor.readRecord()
		if err == io.EOF {
			log.Printf("unexpected eof! reclen=%d totallen=%d", len(rec), f.readCount)
			f.readErr = io.ErrUnexpectedEOF
			return 0, f.readErr
		} else if err != nil {
			f.readErr = err
			return 0, err
		}
		// log.Println("read chunk", len(rec))
		f.buf = rec
	}

	n := copy(p, f.buf)
	f.buf = f.buf[n:]
	f.readCount += n
	f.sha256.Write(p[:n])
	if f.readCount >= f.Bytes {
		f.readErr = io.EOF

		sum := f.sha256.Sum(nil)
		ack := fileTransportAck{
			Ack:    "ok",
			SHA256: fmt.Sprintf("%x", sum),
		}

		msg, _ := json.Marshal(ack)
		f.cryptor.writeRecord(msg)
		f.cryptor.Close()
	}

	return n, nil
}

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
	transport := newFileTransport(transitKey, appID, c.relayAddr())

	transitMsg, err := transport.makeTransitMsg()
	if err != nil {
		return nil, fmt.Errorf("Make transit msg error: %s", err)
	}

	err = clientProto.WriteAppData(ctx, &genericMessage{
		Transit: transitMsg,
	})
	if err != nil {
		return nil, err
	}

	answer := &genericMessage{
		Answer: &answerMsg{
			FileAck: "ok",
		},
	}

	err = clientProto.WriteAppData(ctx, answer)
	if err != nil {
		return nil, err
	}

	log.Printf("try connect direct")
	conn, err := transport.connectDirect(collector.transit)
	if err != nil {
		return nil, err
	}

	if conn == nil {
		log.Printf("try connect direct relay")
		conn, err = transport.connectViaRelay(collector.transit)
		if err != nil {
			return nil, err
		}
	}

	if conn == nil {
		return nil, errors.New("Failed to establish connection")
	}

	log.Printf("start cryptor with %s %s", conn.RemoteAddr(), conn.LocalAddr())
	cryptor := newTransportCryptor(conn, transitKey, "transit_record_sender_key", "transit_record_receiver_key")

	fr.cryptor = cryptor
	fr.sha256 = sha256.New()

	return &fr, nil
}
