package wormhole

import (
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"log"
)

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
