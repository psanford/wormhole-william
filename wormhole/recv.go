package wormhole

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"strings"

	"github.com/psanford/wormhole-william/internal/crypto"
	"github.com/psanford/wormhole-william/rendezvous"
)

// Receive receives a message sent by a wormhole client.
//
// It returns an IncomingMessage with metadata about the payload being sent.
// To read the contents of the message call IncomingMessage.Read().
func (c *Client) Receive(ctx context.Context, code string) (fr *IncomingMessage, returnErr error) {
	sideID := crypto.RandSideID()
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

	if c.VerifierOk != nil {
		verifier, err := clientProto.Verifier()
		if err != nil {
			return nil, err
		}

		if ok := c.VerifierOk(hex.EncodeToString(verifier)); !ok {
			errMsg := "sender rejected verification check, abandoned transfer"
			writeErr := clientProto.WriteAppData(ctx, &genericMessage{
				Error: &errMsg,
			})
			if writeErr != nil {
				return nil, writeErr
			}

			return nil, errors.New(errMsg)
		}
	}

	collector, err := clientProto.Collect(collectOffer, collectTransit)
	if err != nil {
		return nil, err
	}
	defer collector.close()

	var offer offerMsg
	err = collector.waitFor(&offer)
	if err != nil {
		return nil, err
	}

	fr = &IncomingMessage{}

	if offer.Message != nil {
		answer := genericMessage{
			Answer: &answerMsg{
				MessageAck: "ok",
			},
		}

		err = clientProto.WriteAppData(ctx, &answer)
		if err != nil {
			return nil, err
		}

		fr.Type = TransferText
		fr.textReader = bytes.NewReader([]byte(*offer.Message))
		return fr, nil
	} else if offer.File != nil {
		fr.Type = TransferFile
		fr.Name = offer.File.FileName
		fr.TransferBytes = int(offer.File.FileSize)
		fr.UncompressedBytes = int(offer.File.FileSize)
		fr.FileCount = 1
	} else if offer.Directory != nil {
		fr.Type = TransferDirectory
		fr.Name = offer.Directory.Dirname
		fr.TransferBytes = int(offer.Directory.ZipSize)
		fr.UncompressedBytes = int(offer.Directory.NumBytes)
		fr.FileCount = int(offer.Directory.NumFiles)
	} else {
		return nil, errors.New("Got non-file transfer offer")
	}

	var gotTransitMsg transitMsg
	err = collector.waitFor(&gotTransitMsg)
	if err != nil {
		return nil, err
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

	conn, err := transport.connectDirect(&gotTransitMsg)
	if err != nil {
		return nil, err
	}

	if conn == nil {
		conn, err = transport.connectViaRelay(&gotTransitMsg)
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

	return fr, nil
}

// A IncomingMessage contains information about a payload sent to this wormhole client.
//
// The Type field indicates if the sender sent a single file or a directory.
// If the Type is TransferDirectory then reading from the IncomingMessage will
// read a zip file of the contents of the directory.
type IncomingMessage struct {
	Name              string
	Type              TransferType
	TransferBytes     int
	UncompressedBytes int
	FileCount         int

	textReader io.Reader

	cryptor   *transportCryptor
	buf       []byte
	readCount int
	sha256    hash.Hash

	readErr error
}

// Read the decripted contents sent to this client.
func (f *IncomingMessage) Read(p []byte) (int, error) {
	if f.readErr != nil {
		return 0, f.readErr
	}

	switch f.Type {
	case TransferText:
		return f.readText(p)
	case TransferFile, TransferDirectory:
		return f.readCrypt(p)
	default:
		return 0, fmt.Errorf("Unknown Receiver type %d", f.Type)
	}
}

func (f *IncomingMessage) readText(p []byte) (int, error) {
	return f.textReader.Read(p)
}

func (f *IncomingMessage) readCrypt(p []byte) (int, error) {
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
		f.buf = rec
	}

	n := copy(p, f.buf)
	f.buf = f.buf[n:]
	f.readCount += n
	f.sha256.Write(p[:n])
	if f.readCount >= f.TransferBytes {
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
