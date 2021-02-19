// +build js,wasm

package wasm

import (
	"syscall/js"
)

type Promise struct {
	jsValue js.Value
}

type ResolveFn = func(interface{})
type RejectFn = func(error)
type PromiseFn = func(ResolveFn, RejectFn)

func NewPromise(fn PromiseFn) *Promise {
	constructor := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		// TODO: error handling!!!
		obj := js.Global().Get("Object").New()
		obj.Set("resolve", args[0])
		obj.Set("reject", args[1])
		resolve := func(val interface{}) {
			obj.Call("resolve", val)
		}
		reject := func(err error) {
			obj.Call("reject", err.Error())
		}

		fn(resolve, reject)
		return nil
	})
	jsPromise := js.Global().Get("Promise").New(constructor)
	return &Promise{
		jsValue: jsPromise,
	}
}

func (p *Promise) JSValue() js.Value {
	return p.jsValue
}
