package wormhole

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"github.com/psanford/wormhole-william/internal/crypto"
	"github.com/psanford/wormhole-william/rendezvous"
)

// Receive receives a message sent by a wormhole client.
//
// It returns a FileReceiver with metadata about the file being sent.
// To read the contents of the file call FileReceiver.Read().
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
		fr.Bytes = int(offer.File.FileSize)
		fr.FileCount = 1
	} else if offer.Directory != nil {
		fr.Type = TransferDirectory
		fr.Name = offer.Directory.Dirname
		fr.Bytes = int(offer.Directory.ZipSize)
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
