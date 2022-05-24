package wormhole

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
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
			// don't close our connection in this case
			// wait until the user actually accepts the transfer
			return
		} else if returnErr == errDecryptFailed {
			mood = rendezvous.Scary
		}
		rc.Close(ctx, mood)
	}()

	_, err := rc.Connect(ctx)
	if err != nil {
		return nil, err
	}
	nameplate, err := nameplateFromCode(code)
	if err != nil {
		return nil, err
	}

	err = rc.AttachMailbox(ctx, nameplate)
	if err != nil {
		return nil, err
	}

	clientProto := newClientProtocol(ctx, rc, sideID, appID)

	err = clientProto.WritePake(ctx, code)
	if err != nil {
		return nil, err
	}

	err = clientProto.ReadPake(ctx)
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

		rc.Close(ctx, rendezvous.Happy)

		text := *offer.Message
		fr.TransferBytes = len(text)
		fr.TransferBytes64 = int64(fr.TransferBytes)
		fr.UncompressedBytes = fr.TransferBytes
		fr.UncompressedBytes64 = fr.TransferBytes64

		fr.Type = TransferText
		fr.textReader = strings.NewReader(text)
		return fr, nil
	} else if offer.File != nil {
		fr.Type = TransferFile
		fr.Name = offer.File.FileName
		fr.TransferBytes = int(offer.File.FileSize)
		fr.TransferBytes64 = offer.File.FileSize
		fr.UncompressedBytes = int(offer.File.FileSize)
		fr.UncompressedBytes64 = offer.File.FileSize
		fr.FileCount = 1
		fr.ctx = ctx
	} else if offer.Directory != nil {
		fr.Type = TransferDirectory
		fr.Name = offer.Directory.Dirname
		fr.TransferBytes = int(offer.Directory.ZipSize)
		fr.TransferBytes64 = offer.Directory.ZipSize
		fr.UncompressedBytes = int(offer.Directory.NumBytes)
		fr.UncompressedBytes64 = offer.Directory.NumBytes
		fr.FileCount = int(offer.Directory.NumFiles)
		fr.ctx = ctx
	} else {
		return nil, errors.New("got non-file transfer offer")
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
		return nil, fmt.Errorf("make transit msg error: %s", err)
	}

	err = clientProto.WriteAppData(ctx, &genericMessage{
		Transit: transitMsg,
	})
	if err != nil {
		return nil, err
	}

	reject := func() (initErr error) {
		defer func() {
			mood := rendezvous.Errory
			if returnErr == nil {
				mood = rendezvous.Happy
			} else if returnErr == errDecryptFailed {
				mood = rendezvous.Scary
			}
			rc.Close(ctx, mood)
		}()

		var errStr = "transfer rejected"
		answer := &genericMessage{
			Error: &errStr,
		}
		ctx := context.Background()

		err = clientProto.WriteAppData(ctx, answer)
		if err != nil {
			return err
		}

		return nil
	}

	// defer actually sending the "ok" message until
	// the caller does a read on the IncomingMessage object.
	acceptAndInitialize := func() (initErr error) {
		defer func() {
			mood := rendezvous.Errory
			if returnErr == nil {
				mood = rendezvous.Happy
			} else if returnErr == errDecryptFailed {
				mood = rendezvous.Scary
			}
			rc.Close(ctx, mood)
		}()

		answer := &genericMessage{
			Answer: &answerMsg{
				FileAck: "ok",
			},
		}
		ctx := context.Background()

		err = clientProto.WriteAppData(ctx, answer)
		if err != nil {
			return err
		}

		conn, err := transport.connectDirect(&gotTransitMsg)
		if err != nil {
			return err
		}

		if conn == nil {
			conn, err = transport.connectViaRelay(&gotTransitMsg)
			if err != nil {
				return err
			}
		}

		if conn == nil {
			return errors.New("failed to establish connection")
		}

		cryptor := newTransportCryptor(conn, transitKey, "transit_record_sender_key", "transit_record_receiver_key")

		fr.cryptor = cryptor
		fr.sha256 = sha256.New()
		return nil
	}

	fr.initializeTransfer = acceptAndInitialize
	fr.rejectTransfer = reject

	return fr, nil
}

// A IncomingMessage contains information about a payload sent to this wormhole client.
//
// The Type field indicates if the sender sent a single file or a directory.
// If the Type is TransferDirectory then reading from the IncomingMessage will
// read a zip file of the contents of the directory.
type IncomingMessage struct {
	// Name is the name of the file or directory being transferred.
	Name string
	// The type of file transfer being offered.
	Type TransferType
	// Deprecated: TransferBytes has been replaced with with TransferBytes64
	// to allow transfer of >2 GiB files on 32 bit systems
	TransferBytes int
	// TransferBytes64 is the offered size of the file transfer from the peer.
	// This is expected to be the number of bytes sent over the network to
	// perform the file transfer, however a malicious client could lie about this.
	// The primary purpose of this field is to allow the user to choose to accept
	// or reject the transfer if the file size is unexpected.
	//
	// For client implementation convenience, TransferBytes64 is also set for text messages.
	// Note that the message has already been fully transferred by the time this value is known.
	TransferBytes64 int64
	// Deprecated: UncompressedBytes has been replaced with UncompressedBytes64
	// to allow transfers of > 2 GiB files on 32 bit systems
	UncompressedBytes int
	// UncompressedBytes64 is the offered size of the files on disk post decompression.
	// This is sent from the peer as part of the offer and a malicious peer could lie
	// about this.
	// The primary purpose of this field is to allow the user to choose to accept
	// or reject the transfer if the file size is unexpected.
	//
	// For client implementation convenience, UncompressedBytes64 is also set for text messages.
	// Note that the message has already been fully transferred by the time this value is known.
	UncompressedBytes64 int64
	// FileCount is the number of files in a TransferDirectory offer. This is sent
	// as part of the offer from the peer and a malicious peer could lie about this.
	FileCount int

	textReader io.Reader

	transferInitialized bool
	initializeTransfer  func() error
	rejectTransfer      func() error

	cryptor   *transportCryptor
	buf       []byte
	readCount int64
	sha256    hash.Hash

	readErr error

	ctx context.Context
}

// Read the decrypted contents sent to this client.
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
		return 0, fmt.Errorf("unknown Receiver type %d", f.Type)
	}
}

func (f *IncomingMessage) readText(p []byte) (int, error) {
	return f.textReader.Read(p)
}

// Reject an incoming file or directory transfer. This must be
// called before any calls to Read. This does nothing for
// text message transfers.
func (f *IncomingMessage) Reject() error {
	switch f.Type {
	case TransferFile, TransferDirectory:
	default:
		return errors.New("can only reject File and Directory transfers")
	}

	if f.readErr != nil {
		return f.readErr
	}

	if f.transferInitialized {
		return errors.New("cannot Reject after calls to Read")
	}

	f.transferInitialized = true
	f.rejectTransfer()

	return nil
}

func (f *IncomingMessage) readCrypt(p []byte) (int, error) {
	if f.readErr != nil {
		return 0, f.readErr
	}

	if err := f.ctx.Err(); err != nil {
		f.readErr = err
		if f.cryptor != nil {
			f.cryptor.Close()
		}
		return 0, err
	}

	if !f.transferInitialized {
		f.transferInitialized = true
		err := f.initializeTransfer()
		if err != nil {
			return 0, err
		}
	}

	// for empty files the sender doesn't send any records
	// so we need to short circut the read and proceed straight
	// to sending an "ok" ack
	emptyFile := f.TransferBytes64 == 0

	if len(f.buf) == 0 && !emptyFile {
		rec, err := f.cryptor.readRecord()
		if err == io.EOF {
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
	f.readCount += int64(n)
	f.sha256.Write(p[:n])
	if f.readCount >= f.TransferBytes64 {
		f.readErr = io.EOF

		sum := f.sha256.Sum(nil)
		ack := fileTransportAck{
			Ack:    "ok",
			SHA256: hex.EncodeToString(sum),
		}

		msg, _ := json.Marshal(ack)
		f.cryptor.writeRecord(msg)
		f.cryptor.Close()
	}

	return n, nil
}
