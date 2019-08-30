package wormhole

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/psanford/wormhole-william/internal/crypto"
	"github.com/psanford/wormhole-william/rendezvous"
	"github.com/psanford/wormhole-william/wordlist"
	"golang.org/x/crypto/nacl/secretbox"
)

// SendFile sends a single file via the wormhole protocol. It returns a nameplate+passhrase code to give to the
// receiver, a result channel that will be written to after the receiver attempts to read (either successfully or not)
// and an error if one occured.
func (c *Client) SendFile(ctx context.Context, fileName string, r io.ReadSeeker) (string, chan SendResult, error) {
	if err := c.validateRelayAddr(); err != nil {
		return "", nil, fmt.Errorf("Invalid TransitRelayAddress: %s", err)
	}

	size, err := readSeekerSize(r)
	if err != nil {
		return "", nil, err
	}

	sideID := crypto.RandSideID()
	appID := c.appID()
	rc := rendezvous.NewClient(c.url(), sideID, appID)

	_, err = rc.Connect(ctx)
	if err != nil {
		return "", nil, err
	}

	nameplate, err := rc.CreateMailbox(ctx)
	if err != nil {
		return "", nil, err
	}

	pwStr := nameplate + "-" + wordlist.ChooseWords(c.wordCount())

	clientProto := newClientProtocol(ctx, rc, sideID, appID)

	ch := make(chan SendResult, 1)
	go func() {
		var returnErr error
		defer func() {
			mood := rendezvous.Errory
			if returnErr == nil {
				mood = rendezvous.Happy
			} else if returnErr == errDecryptFailed {
				mood = rendezvous.Scary
			}

			rc.Close(ctx, mood)
		}()

		sendErr := func(err error) {
			ch <- SendResult{
				Error: err,
			}
			returnErr = err
			close(ch)
			return
		}

		err = clientProto.WritePake(ctx, pwStr)
		if err != nil {
			sendErr(err)
			return
		}

		err = clientProto.ReadPake()
		if err != nil {
			sendErr(err)
			return
		}

		err = clientProto.WriteVersion(ctx)
		if err != nil {
			sendErr(err)
			return
		}

		_, err = clientProto.ReadVersion()
		if err != nil {
			sendErr(err)
			return
		}

		transitKey := deriveTransitKey(clientProto.sharedKey, appID)
		transport := newFileTransport(transitKey, appID, c.relayAddr())
		err = transport.listen()
		if err != nil {
			sendErr(err)
			return
		}

		err = transport.listenRelay()
		if err != nil {
			sendErr(err)
			return
		}

		transitMsg, err := transport.makeTransitMsg()
		if err != nil {
			sendErr(fmt.Errorf("Make transit msg error: %s", err))
			return
		}

		err = clientProto.WriteAppData(ctx, &genericMessage{
			Transit: transitMsg,
		})
		if err != nil {
			sendErr(err)
			return
		}

		offer := &genericMessage{
			Offer: &offerMsg{
				File: &offerFile{
					FileName: fileName,
					FileSize: size,
				},
			},
		}
		err = clientProto.WriteAppData(ctx, offer)
		if err != nil {
			sendErr(err)
			return
		}

		collector, err := clientProto.Collect(collectTransit, collectAnswer)
		if err != nil {
			sendErr(err)
			return
		}

		if collector.answer.FileAck != "ok" {
			sendErr(fmt.Errorf("Unexpected answer"))
			return
		}

		conn, err := transport.acceptConnection(ctx)
		if err != nil {
			sendErr(err)
			return
		}

		cryptor := newTransportCryptor(conn, transitKey, "transit_record_receiver_key", "transit_record_sender_key")

		recordSize := (1 << 14)
		// chunk
		recordSlice := make([]byte, recordSize-secretbox.Overhead)
		hasher := sha256.New()

		for {
			n, err := r.Read(recordSlice)
			if n > 0 {
				hasher.Write(recordSlice[:n])
				err = cryptor.writeRecord(recordSlice[:n])
				if err != nil {
					sendErr(err)
					return
				}
			}
			if err == io.EOF {
				break
			} else if err != nil {
				sendErr(err)
				return
			}
		}

		respRec, err := cryptor.readRecord()
		if err != nil {
			sendErr(err)
			return
		}

		var ack fileTransportAck
		err = json.Unmarshal(respRec, &ack)
		if err != nil {
			sendErr(err)
			return
		}

		if ack.Ack != "ok" {
			sendErr(errors.New("Got non ok final ack from receiver"))
			return
		}

		shaSum := fmt.Sprintf("%x", hasher.Sum(nil))
		if strings.ToLower(ack.SHA256) != shaSum {
			sendErr(fmt.Errorf("Receiver sha256 mismatch %s vs %s", ack.SHA256, shaSum))
			return
		}

		ch <- SendResult{
			OK: true,
		}
		close(ch)
		return
	}()

	return pwStr, ch, nil
}

// A DirectoryEntry represents a single file to be sent by SendDirectory
type DirectoryEntry struct {
	// Path is the relative path to the file from the top level directory.
	Path string

	// Mode controls the permission and mode bits for the file.
	Mode os.FileMode

	// Reader is a function that returns a ReadCloser for the file's content.
	Reader func() (io.ReadCloser, error)
}

// SendDirectory sends a tree of files to a receiving client.
// Each DirectoryEntry Path must be prefixed by the directoryName provided to SendDirectory.
//
// It returns a nameplate+passhrase code to give to the
// receiver, a result channel that will be written to after the receiver attempts to read (either successfully or not)
// and an error if one occured.
func (c *Client) SendDirectory(ctx context.Context, directoryName string, entries []DirectoryEntry) (string, chan SendResult, error) {
	zipInfo, err := makeTmpZip(directoryName, entries)
	if err != nil {
		return "", nil, err
	}

	sideID := crypto.RandSideID()
	appID := c.appID()
	rc := rendezvous.NewClient(c.url(), sideID, appID)

	_, err = rc.Connect(ctx)
	if err != nil {
		return "", nil, err
	}

	nameplate, err := rc.CreateMailbox(ctx)
	if err != nil {
		return "", nil, err
	}

	pwStr := nameplate + "-" + wordlist.ChooseWords(c.wordCount())

	clientProto := newClientProtocol(ctx, rc, sideID, appID)

	ch := make(chan SendResult, 1)
	go func() {
		var returnErr error
		defer func() {
			mood := rendezvous.Errory
			if returnErr == nil {
				mood = rendezvous.Happy
			} else if returnErr == errDecryptFailed {
				mood = rendezvous.Scary
			}

			rc.Close(ctx, mood)
		}()
		defer zipInfo.file.Close()

		sendErr := func(err error) {
			ch <- SendResult{
				Error: err,
			}
			returnErr = err
			close(ch)
			return
		}

		err = clientProto.WritePake(ctx, pwStr)
		if err != nil {
			sendErr(err)
			return
		}

		err = clientProto.ReadPake()
		if err != nil {
			sendErr(err)
			return
		}

		err = clientProto.WriteVersion(ctx)
		if err != nil {
			sendErr(err)
			return
		}

		_, err = clientProto.ReadVersion()
		if err != nil {
			sendErr(err)
			return
		}

		transitKey := deriveTransitKey(clientProto.sharedKey, appID)
		transport := newFileTransport(transitKey, appID, c.relayAddr())
		err = transport.listen()
		if err != nil {
			sendErr(err)
			return
		}

		err = transport.listenRelay()
		if err != nil {
			sendErr(err)
			return
		}

		transitMsg, err := transport.makeTransitMsg()
		if err != nil {
			sendErr(fmt.Errorf("Make transit msg error: %s", err))
			return
		}

		err = clientProto.WriteAppData(ctx, &genericMessage{
			Transit: transitMsg,
		})
		if err != nil {
			sendErr(err)
			return
		}

		offer := &genericMessage{
			Offer: &offerMsg{
				Directory: &offerDirectory{
					Dirname:  directoryName,
					Mode:     "zipfile/deflated",
					NumBytes: zipInfo.numBytes,
					NumFiles: zipInfo.numFiles,
					ZipSize:  zipInfo.zipSize,
				},
			},
		}
		err = clientProto.WriteAppData(ctx, offer)
		if err != nil {
			sendErr(err)
			return
		}

		collector, err := clientProto.Collect(collectTransit, collectAnswer)
		if err != nil {
			sendErr(err)
			return
		}

		if collector.answer.FileAck != "ok" {
			sendErr(fmt.Errorf("Unexpected answer"))
			return
		}

		conn, err := transport.acceptConnection(ctx)
		if err != nil {
			sendErr(err)
			return
		}

		cryptor := newTransportCryptor(conn, transitKey, "transit_record_receiver_key", "transit_record_sender_key")

		recordSize := (1 << 14)
		// chunk
		recordSlice := make([]byte, recordSize-secretbox.Overhead)
		hasher := sha256.New()

		for {
			n, err := zipInfo.file.Read(recordSlice)
			if n > 0 {
				hasher.Write(recordSlice[:n])
				err = cryptor.writeRecord(recordSlice[:n])
				if err != nil {
					sendErr(err)
					return
				}
			}
			if err == io.EOF {
				break
			} else if err != nil {
				sendErr(err)
				return
			}
		}

		respRec, err := cryptor.readRecord()
		if err != nil {
			sendErr(err)
			return
		}

		var ack fileTransportAck
		err = json.Unmarshal(respRec, &ack)
		if err != nil {
			sendErr(err)
			return
		}

		if ack.Ack != "ok" {
			sendErr(errors.New("Got non ok final ack from receiver"))
			return
		}

		shaSum := fmt.Sprintf("%x", hasher.Sum(nil))
		if strings.ToLower(ack.SHA256) != shaSum {
			sendErr(fmt.Errorf("Receiver sha256 mismatch %s vs %s", ack.SHA256, shaSum))
			return
		}

		ch <- SendResult{
			OK: true,
		}
		close(ch)
		return
	}()

	return pwStr, ch, nil

}

type zipResult struct {
	file     *os.File
	numBytes int64
	numFiles int64
	zipSize  int64
}

func makeTmpZip(directoryName string, entries []DirectoryEntry) (*zipResult, error) {
	f, err := ioutil.TempFile("", "wormhole-william-dir")
	if err != nil {
		return nil, err
	}

	if len(entries) < 1 {
		return nil, errors.New("No files provided")
	}

	defer os.Remove(f.Name())

	if strings.TrimSpace(directoryName) == "" {
		return nil, errors.New("directoryName must be set")
	}

	prefix, _ := filepath.Split(directoryName)
	if prefix != "" {
		return nil, errors.New("directoryName must not include sub directories")
	}

	w := zip.NewWriter(f)

	var totalBytes int64

	for _, entry := range entries {
		if !strings.HasPrefix(entry.Path, directoryName+"/") {
			return nil, errors.New("Each directory entry must be prefixed with the directoryName")
		}

		header := &zip.FileHeader{
			Name:   strings.TrimPrefix(entry.Path, directoryName+"/"),
			Method: zip.Deflate,
		}
		header.SetMode(entry.Mode)
		f, err := w.CreateHeader(header)
		if err != nil {
			return nil, err
		}
		r, err := entry.Reader()
		if err != nil {
			return nil, err
		}

		var counter countWriter

		_, err = io.Copy(f, io.TeeReader(r, &counter))
		if err != nil {
			return nil, err
		}

		totalBytes = totalBytes + counter.count

		err = r.Close()
		if err != nil {
			return nil, err
		}
	}

	err = w.Close()
	if err != nil {
		return nil, err
	}

	zipSize, err := readSeekerSize(f)
	if err != nil {
		return nil, err
	}
	result := zipResult{
		file:     f,
		numBytes: totalBytes,
		numFiles: int64(len(entries)),
		zipSize:  zipSize,
	}

	return &result, nil
}

type countWriter struct {
	count int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	c.count = c.count + int64(len(p))
	return len(p), nil
}

func readSeekerSize(r io.ReadSeeker) (int64, error) {
	size, err := r.Seek(0, io.SeekEnd)
	if err != nil {
		return -1, err
	}

	_, err = r.Seek(0, io.SeekStart)
	if err != nil {
		return -1, err
	}

	return size, nil

}
