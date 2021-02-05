package wasm

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"syscall/js"
	"unsafe"

	"github.com/psanford/wormhole-william/wormhole"
)

type ClientMap = map[uintptr]*wormhole.Client

// TODO: automate use of `-ld -X` with env vars
const DEFAULT_APP_ID = "myFileTransfer"
const DEFAULT_RENDEZVOUS_URL = "http://localhost:4000/v1"
const DEFAULT_TRANSIT_RELAY_ADDRESS = "ws://localhost:4001"
const DEFAULT_PASSPHRASE_COMPONENT_LENGTH = 2
const MAX_FILE_SIZE = 100000000 // bytes

var (
	ErrClientNotFound = fmt.Errorf("%s", "wormhole client not found")

	clientMap ClientMap
)

func init() {
	clientMap = make(ClientMap)
}

func NewClient(this js.Value, args []js.Value) interface{} {
	var (
		config js.Value
		object = js.Global().Get("Object")
	)
	if len(args) > 0 && args[0].InstanceOf(object) {
		config = args[0]
	} else {
		config = object.New()
	}

	// read from config
	appID := config.Get("appID")
	rendezvousURL := config.Get("rendezvousURL")
	transitRelayAddress := config.Get("transitRelayAddress")
	passPhraseComponentLength := config.Get("passPhraseComponentLength")

	//overwrite config with defaults where falsy
	//TODO: use constants for property names?
	if !appID.Truthy() {
		config.Set("appID", DEFAULT_APP_ID)
	}
	if !rendezvousURL.Truthy() {
		config.Set("rendezvousURL", DEFAULT_RENDEZVOUS_URL)
	}
	if !transitRelayAddress.Truthy() {
		config.Set("transitRelayAddress", DEFAULT_TRANSIT_RELAY_ADDRESS)
	}
	if !passPhraseComponentLength.Truthy() {
		config.Set("passPhraseComponentLength", DEFAULT_PASSPHRASE_COMPONENT_LENGTH)
	}

	// read config with defaults merged
	appID = config.Get("appID")
	rendezvousURL = config.Get("rendezvousURL")
	transitRelayAddress = config.Get("transitRelayAddress")
	passPhraseComponentLength = config.Get("passPhraseComponentLength")

	client := &wormhole.Client{
		AppID:                     appID.String(),
		RendezvousURL:             rendezvousURL.String(),
		TransitRelayAddress:       transitRelayAddress.String(),
		PassPhraseComponentLength: passPhraseComponentLength.Int(),
	}
	clientPtr := uintptr(unsafe.Pointer(client))
	clientMap[clientPtr] = client

	return clientPtr
}

func Client_SendText(this js.Value, args []js.Value) interface{} {
	ctx := context.Background()
	fmt.Printf("this: %v\n", this)

	return NewPromise(func(resolve ResolveFn, reject RejectFn) {
		if len(args) != 2 {
			reject(fmt.Errorf("invalid number of arguments: %d. expected: %d", len(args), 2))
			return
		}

		clientPtr := uintptr(args[0].Int())
		msg := args[1].String()
		err, client := getClient(clientPtr)
		if err != nil {
			reject(err)
			return
		}

		go func() {
			code, _, err := client.SendText(ctx, msg)
			if err != nil {
				reject(err)
				return
			}
			resolve(code)
		}()
	})
}

func Client_SendFile(this js.Value, args []js.Value) interface{} {
	ctx := context.Background()
	fmt.Printf("this: %v\n", this)

	return NewPromise(func(resolve ResolveFn, reject RejectFn) {
		if len(args) != 3 {
			reject(fmt.Errorf("invalid number of arguments: %d. expected: %d", len(args), 3))
			return
		}

		clientPtr := uintptr(args[0].Int())
		fileName := args[1].String()

		// TODO: something better!
		fileData := make([]byte, MAX_FILE_SIZE)
		js.CopyBytesToGo(fileData, args[2])
		fileReader := bytes.NewReader(fileData)

		err, client := getClient(clientPtr)
		if err != nil {
			reject(err)
			return
		}

		go func() {
			code, _, err := client.SendFile(ctx, fileName, fileReader)
			if err != nil {
				reject(err)
				return
			}
			resolve(code)
		}()
	})
}

func Client_RecvText(this js.Value, args []js.Value) interface{} {
	ctx := context.Background()

	return NewPromise(func(resolve ResolveFn, reject RejectFn) {
		if len(args) != 2 {
			reject(fmt.Errorf("invalid number of arguments: %d. expected: %d", len(args), 2))
			return
		}

		clientPtr := uintptr(args[0].Int())
		code := args[1].String()
		err, client := getClient(clientPtr)
		if err != nil {
			reject(err)
			return
		}

		go func() {
			msg, err := client.Receive(ctx, code)
			if err != nil {
				reject(err)
				return
			}

			msgBytes, err := ioutil.ReadAll(msg)
			if err != nil {
				reject(err)
				return
			}
			resolve(string(msgBytes))
		}()
	}).JSValue()
}

func Client_RecvFile(this js.Value, args []js.Value) interface{} {
	ctx := context.Background()

	return NewPromise(func(resolve ResolveFn, reject RejectFn) {
		if len(args) != 2 {
			reject(fmt.Errorf("invalid number of arguments: %d. expected: %d", len(args), 2))
			return
		}

		clientPtr := uintptr(args[0].Int())
		code := args[1].String()
		err, client := getClient(clientPtr)
		if err != nil {
			reject(err)
			return
		}

		go func() {
			fmt.Println("client.Receive...")
			msg, err := client.Receive(ctx, code)
			fmt.Println("...done")
			if err != nil {
				fmt.Printf("err: %s\n", err)
				reject(err)
				return
			}

			fmt.Println("ioutil.ReadAll...")
			msgBytes, err := ioutil.ReadAll(msg)
			if err != nil {
				reject(err)
				return
			}

			// TODO: something better!
			fmt.Println("copying bytes")
			jsData := js.Global().Get("Uint8Array").New(MAX_FILE_SIZE)
			js.CopyBytesToJS(jsData, msgBytes)
			resolve(jsData)
		}()
	}).JSValue()
}

func Client_free(jsClient js.Value, args []js.Value) interface{} {
	if len(args) != 1 {
		return fmt.Errorf("invalid number of arguments: %d. expected: %d", len(args), 2)
	}

	clientPtr := uintptr(args[0].Int())
	delete(clientMap, clientPtr)
	return nil
}

func getClient(clientPtr uintptr) (error, *wormhole.Client) {
	client, ok := clientMap[clientPtr]
	if !ok {
		fmt.Println("clientMap entry missing")
		return ErrClientNotFound, nil
	}

	return nil, client
}
