package wormhole

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/psanford/wormhole-william/random"
	"github.com/psanford/wormhole-william/rendezvous"
	"github.com/psanford/wormhole-william/wordlist"
	"golang.org/x/crypto/nacl/secretbox"
)

func (c *Client) SendFile(ctx context.Context, fileName string, r io.ReadSeeker) (string, chan SendResult, error) {
	if err := c.validateRelayAddr(); err != nil {
		return "", nil, fmt.Errorf("Invalid TransitRelayAddress: %s", err)
	}

	size, err := r.Seek(0, io.SeekEnd)
	if err != nil {
		return "", nil, err
	}

	_, err = r.Seek(0, io.SeekStart)
	if err != nil {
		return "", nil, err
	}

	sideID := random.SideID()
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

// func (c *Client) SendDirectory(ctx context.Context, directoryPath string) {
// }
