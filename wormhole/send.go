package wormhole

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zip"
	"github.com/psanford/wormhole-william/internal/crypto"
	"github.com/psanford/wormhole-william/rendezvous"
	"github.com/psanford/wormhole-william/wordlist"
	"golang.org/x/crypto/nacl/secretbox"
)

// SendText sends a text message via the wormhole protocol.
//
// It returns the nameplate+passphrase code to give to the receiver, a result chan
// that gets written to once the receiver actually attempts to read the message
// (either successfully or not).
func (c *Client) SendText(ctx context.Context, msg string, opts ...SendOption) (string, chan SendResult, error) {
	sideID := crypto.RandSideID()
	appID := c.appID()

	var options sendOptions
	for _, opt := range opts {
		err := opt.setOption(&options)
		if err != nil {
			return "", nil, err
		}
	}

	rc := rendezvous.NewClient(c.url(), sideID, appID)

	_, err := rc.Connect(ctx)
	if err != nil {
		return "", nil, err
	}

	var pwStr string
	if options.code == "" {
		nameplate, err := rc.CreateMailbox(ctx)
		if err != nil {
			return "", nil, err
		}

		pwStr = nameplate + "-" + wordlist.ChooseWords(c.wordCount())
	} else {
		pwStr = options.code
		nameplate, err := nameplateFromCode(pwStr)
		if err != nil {
			return "", nil, err
		}

		err = rc.AttachMailbox(ctx, nameplate)
		if err != nil {
			return "", nil, err
		}
	}

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
		}

		err = clientProto.WritePake(ctx, pwStr)
		if err != nil {
			sendErr(err)
			return
		}

		err = clientProto.ReadPake(ctx)
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

		if c.VerifierOk != nil {
			verifier, err := clientProto.Verifier()
			if err != nil {
				sendErr(err)
				return
			}

			if ok := c.VerifierOk(hex.EncodeToString(verifier)); !ok {
				errMsg := "sender rejected verification check, abandoned transfer"
				writeErr := clientProto.WriteAppData(ctx, &genericMessage{
					Error: &errMsg,
				})
				if writeErr != nil {
					sendErr(writeErr)
					return
				}

				sendErr(errors.New(errMsg))
				return
			}
		}

		offer := &genericMessage{
			Offer: &offerMsg{
				Message: &msg,
			},
		}
		err = clientProto.WriteAppData(ctx, offer)
		if err != nil {
			sendErr(err)
			return
		}

		collector, err := clientProto.Collect()
		if err != nil {
			sendErr(err)
			return
		}
		defer collector.close()

		var answer answerMsg
		err = collector.waitFor(&answer)
		if err != nil {
			sendErr(err)
			return
		}

		if answer.MessageAck == "ok" {
			if options.progressFunc != nil {
				// If called WithProgress, send a single progress update
				// showing that the transfer is complete. This is to simplify
				// client implementations that share code between the Send()
				// and SendText() code paths.
				msgSize := int64(len(msg))
				options.progressFunc(msgSize, msgSize)
			}

			ch <- SendResult{
				OK: true,
			}
			close(ch)
			return
		} else {
			sendErr(fmt.Errorf("unexpected answer"))
			return
		}
	}()

	return pwStr, ch, nil
}

func (c *Client) sendFileDirectory(ctx context.Context, offer *offerMsg, r io.Reader, opts ...SendOption) (string, chan SendResult, error) {
	if err := c.validateRelayAddr(); err != nil {
		return "", nil, fmt.Errorf("invalid TransitRelayAddress: %s", err)
	}

	var options sendOptions
	for _, opt := range opts {
		err := opt.setOption(&options)
		if err != nil {
			return "", nil, err
		}
	}

	sideID := crypto.RandSideID()
	appID := c.appID()
	rc := rendezvous.NewClient(c.url(), sideID, appID)

	_, err := rc.Connect(ctx)
	if err != nil {
		return "", nil, err
	}

	var pwStr string
	if options.code == "" {
		nameplate, err := rc.CreateMailbox(ctx)
		if err != nil {
			return "", nil, err
		}

		pwStr = nameplate + "-" + wordlist.ChooseWords(c.wordCount())
	} else {
		pwStr = options.code
		nameplate, err := nameplateFromCode(pwStr)
		if err != nil {
			return "", nil, err
		}

		err = rc.AttachMailbox(ctx, nameplate)
		if err != nil {
			return "", nil, err
		}
	}

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
		}

		err = clientProto.WritePake(ctx, pwStr)
		if err != nil {
			sendErr(err)
			return
		}

		err = clientProto.ReadPake(ctx)
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
		if c.VerifierOk != nil {
			verifier, err := clientProto.Verifier()
			if err != nil {
				sendErr(err)
				return
			}

			if ok := c.VerifierOk(hex.EncodeToString(verifier)); !ok {
				errMsg := "sender rejected verification check, abandoned transfer"
				writeErr := clientProto.WriteAppData(ctx, &genericMessage{
					Error: &errMsg,
				})
				if writeErr != nil {
					sendErr(writeErr)
					return
				}

				sendErr(errors.New(errMsg))
				return
			}
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

		transit, err := transport.makeTransitMsg()
		if err != nil {
			sendErr(fmt.Errorf("make transit msg error: %s", err))
			return
		}

		err = clientProto.WriteAppData(ctx, &genericMessage{
			Transit: transit,
		})
		if err != nil {
			sendErr(err)
			return
		}

		gmOffer := &genericMessage{
			Offer: offer,
		}
		err = clientProto.WriteAppData(ctx, gmOffer)
		if err != nil {
			sendErr(err)
			return
		}

		collector, err := clientProto.Collect()
		if err != nil {
			sendErr(err)
			return
		}
		defer collector.close()

		var answer answerMsg
		err = collector.waitFor(&answer)
		if err != nil {
			sendErr(err)
			return
		}

		if answer.FileAck != "ok" {
			sendErr(fmt.Errorf("unexpected answer"))
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

		var (
			progress  int64
			totalSize int64
		)
		if offer.File != nil {
			totalSize = offer.File.FileSize
		} else if offer.Directory != nil {
			totalSize = offer.Directory.ZipSize
		}

		var cancel func()
		ctx, cancel = context.WithCancel(ctx)
		defer cancel()

		go func() {
			<-ctx.Done()
			conn.Close()
		}()

		for {
			n, err := r.Read(recordSlice)
			if n > 0 {
				hasher.Write(recordSlice[:n])
				err = cryptor.writeRecord(recordSlice[:n])
				if err != nil {
					sendErr(err)
					return
				}
				progress += int64(n)
				if options.progressFunc != nil {
					options.progressFunc(progress, totalSize)
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
			sendErr(errors.New("got non ok final ack from receiver"))
			return
		}

		shaSum := hex.EncodeToString(hasher.Sum(nil))
		if strings.ToLower(ack.SHA256) != shaSum {
			sendErr(fmt.Errorf("receiver sha256 mismatch %s vs %s", ack.SHA256, shaSum))
			return
		}

		ch <- SendResult{
			OK: true,
		}
		close(ch)
	}()

	return pwStr, ch, nil
}

// SendFile sends a single file via the wormhole protocol. It returns a nameplate+passhrase code to give to the
// receiver, a result channel that will be written to after the receiver attempts to read (either successfully or not)
// and an error if one occurred.
func (c *Client) SendFile(ctx context.Context, fileName string, r io.ReadSeeker, opts ...SendOption) (string, chan SendResult, error) {
	if err := c.validateRelayAddr(); err != nil {
		return "", nil, fmt.Errorf("invalid TransitRelayAddress: %s", err)
	}

	size, err := readSeekerSize(r)
	if err != nil {
		return "", nil, err
	}

	offer := &offerMsg{
		File: &offerFile{
			FileName: fileName,
			FileSize: size,
		},
	}

	return c.sendFileDirectory(ctx, offer, r, opts...)
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
// and an error if one occurred.
func (c *Client) SendDirectory(ctx context.Context, directoryName string, entries []DirectoryEntry, opts ...SendOption) (string, chan SendResult, error) {
	zipInfo, err := makeTmpZip(directoryName, entries)
	if err != nil {
		return "", nil, err
	}

	offer := &offerMsg{
		Directory: &offerDirectory{
			Dirname:  directoryName,
			Mode:     "zipfile/deflated",
			NumBytes: zipInfo.numBytes,
			NumFiles: zipInfo.numFiles,
			ZipSize:  zipInfo.zipSize,
		},
	}

	code, resultCh, err := c.sendFileDirectory(ctx, offer, zipInfo.file, opts...)
	if err != nil {
		return "", nil, err
	}

	// intercept result chan to close our tmpfile after we are done with it
	retCh := make(chan SendResult, 1)
	go func() {
		r := <-resultCh
		zipInfo.file.Close()
		retCh <- r
	}()

	return code, retCh, err
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
		return nil, errors.New("no files provided")
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

	prefixPath := filepath.ToSlash(directoryName) + "/"

	for _, entry := range entries {
		entryPath := filepath.ToSlash(entry.Path)

		if !strings.HasPrefix(entryPath, prefixPath) {
			return nil, errors.New("each directory entry must be prefixed with the directoryName")
		}

		header := &zip.FileHeader{
			Name:   strings.TrimPrefix(entryPath, prefixPath),
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

		n, err := io.Copy(f, r)
		if err != nil {
			return nil, err
		}

		totalBytes += n

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

type sendOptions struct {
	code         string
	progressFunc progressFunc
}

type SendOption interface {
	setOption(*sendOptions) error
}

type sendCodeOption struct {
	code string
}

func (o sendCodeOption) setOption(opts *sendOptions) error {
	if err := validateCode(o.code); err != nil {
		return err
	}

	opts.code = o.code
	return nil
}

func validateCode(code string) error {
	if code == "" {
		return nil
	}
	_, err := nameplateFromCode(code)
	if err != nil {
		return err
	}
	if strings.Contains(code, " ") {
		return errors.New("code must not contain spaces")
	}
	return nil
}

// WithCode returns a SendOption to use a specific nameplate+code
// instead of generating one dynamically.
func WithCode(code string) SendOption {
	return sendCodeOption{code: code}
}

type progressFunc func(sentBytes int64, totalBytes int64)

type progressSendOption struct {
	progressFunc progressFunc
}

func (o progressSendOption) setOption(opts *sendOptions) error {
	opts.progressFunc = o.progressFunc
	return nil
}

// WithProgress returns a SendOption to track the progress of the data
// transfer. It takes a callback function that will be called for each
// chunk of data successfully written.
//
// WithProgress is only minimally supported in SendText. SendText does
// not use the wormhole transit protocol so it is not able to detect
// the progress of the receiver. This limitation does not apply to
// SendFile or SendDirectory.
func WithProgress(f func(sentBytes int64, totalBytes int64)) SendOption {
	return progressSendOption{f}
}
