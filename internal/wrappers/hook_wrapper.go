package wrappers

import "reflect"

type HookWrapper struct {
	// hook's function's value
	v reflect.Value
}

func WrapHook(hook any) HookWrapper {
	hookT := reflect.TypeOf(hook)
	hookV := reflect.ValueOf(hook)

	if hookT.Kind() != reflect.Func {
		panic("hook should be function")
	}

	return HookWrapper{
		v: hookV,
	}
}

// Calls hook, starts it in new gorutine
// TODO add customization of, do we need to start in new gorutine
func (wh *HookWrapper) Call(pl PayloadWrapper) {
	go func(input PayloadWrapper) {
		args := []reflect.Value{
			reflect.ValueOf(input.Original()).Elem(),
		}
		wh.v.Call(args)
	}(pl)
}
