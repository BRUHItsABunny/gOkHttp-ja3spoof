package gokhttp_ja3spoof

import (
	"net/http"

	oohttp "github.com/BRUHItsABunny/oohttp"
)

type HTTP2ParametersOption struct {
	HeaderTableSize      int64
	EnablePush           int64
	MaxConcurrentStreams int64
	InitialWindowSize    int64
	MaxFrameSize         int64
	MaxHeaderListSize    int64
	AdditionalValues     []int64

	WindowUpdateIncrement uint32

	HTTP2PriorityFrameSettings *oohttp.HTTP2PriorityFrameSettings
}

func (o *HTTP2ParametersOption) Execute(client *http.Client) error {
	typedTrans, ok := client.Transport.(*oohttp.StdlibTransport)
	if ok {
		typedTrans.Transport.HasCustomInitialSettings = true
		typedTrans.Transport.HTTP2SettingsFrameParameters = append(
			[]int64{
				o.HeaderTableSize,
				o.EnablePush,
				o.MaxConcurrentStreams,
				o.InitialWindowSize,
				o.MaxFrameSize,
				o.MaxHeaderListSize,
			}, o.AdditionalValues...)

		typedTrans.Transport.HasCustomWindowUpdate = true
		typedTrans.Transport.WindowUpdateIncrement = o.WindowUpdateIncrement
		typedTrans.Transport.HTTP2PriorityFrameSettings = o.HTTP2PriorityFrameSettings
	}
	return nil
}
