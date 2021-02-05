package main

import (
	"syscall/js"

	"github.com/psanford/wormhole-william/wasm"
)

func main() {
	// make things available in JS global scope (i.e. `window` in browsers).
	js.Global().Set("newWormholeClient", js.FuncOf(wasm.NewClient))
	js.Global().Set("client_free", js.FuncOf(wasm.Client_free))
	js.Global().Set("client_sendText", js.FuncOf(wasm.Client_SendText))
	js.Global().Set("client_sendFile", js.FuncOf(wasm.Client_SendFile))
	js.Global().Set("client_recvText", js.FuncOf(wasm.Client_RecvText))
	js.Global().Set("client_recvFile", js.FuncOf(wasm.Client_RecvFile))

	// block to keep the wasm module API available
	// (see: )
	<-make(chan bool)
}
