package unihttpstream

import (
	"io"
	"net/http"
	"time"

	"github.com/centrifugal/centrifugo/v6/internal/logging"
	"github.com/centrifugal/centrifugo/v6/internal/tools"

	"github.com/centrifugal/centrifuge"
	"github.com/centrifugal/protocol"
	"github.com/rs/zerolog/log"
	"github.com/segmentio/encoding/json"
)

type Handler struct {
	node     *centrifuge.Node
	config   Config
	pingPong centrifuge.PingPongConfig
}

func NewHandler(n *centrifuge.Node, c Config, pingPong centrifuge.PingPongConfig) *Handler {
	return &Handler{
		node:     n,
		config:   c,
		pingPong: pingPong,
	}
}

const streamWriteTimeout = time.Second

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Max-Age", "300")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	_, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "expected http.ResponseWriter to be http.Flusher", http.StatusInternalServerError)
		return
	}
	var req *protocol.ConnectRequest

	maxBytesSize := int64(h.config.MaxRequestBodySize)
	r.Body = http.MaxBytesReader(w, r.Body, maxBytesSize)
	connectRequestData, err := io.ReadAll(r.Body)
	if err != nil {
		log.Info().Err(err).Str("transport", transportName).Msg("error reading uni http stream request body")
		if len(connectRequestData) >= int(maxBytesSize) {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		return
	}
	_, err = json.Parse(connectRequestData, &req, json.ZeroCopy)
	if err != nil {
		if logging.Enabled(logging.DebugLevel) {
			log.Debug().Err(err).Str("transport", transportName).Msg("malformed connect request")
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	transport := newStreamTransport(r, h.pingPong)
	c, closeFn, err := centrifuge.NewClient(r.Context(), h.node, transport)
	if err != nil {
		log.Error().Err(err).Str("transport", transportName).Msg("error create client")
		return
	}
	defer func() { _ = closeFn() }()
	defer close(transport.closedCh) // need to execute this after client closeFn.

	if logging.Enabled(logging.DebugLevel) {
		log.Debug().Str("transport", transportName).Str("client", c.ID()).Msg("client connection established")
		defer func(started time.Time) {
			log.Debug().Str("transport", transportName).Str("client", c.ID()).
				Str("duration", time.Since(started).String()).Msg("client connection completed")
		}(time.Now())
	}

	if h.config.ConnectCodeToHTTPResponse.Enabled {
		err = c.ProtocolConnectNoErrorToDisconnect(req)
		if err != nil {
			resp, ok := tools.ConnectErrorToToHTTPResponse(err, h.config.ConnectCodeToHTTPResponse.Transforms)
			if ok {
				w.WriteHeader(resp.StatusCode)
				_, _ = w.Write([]byte(resp.Body))
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
			return
		}
	} else {
		c.ProtocolConnect(req)
	}

	if r.ProtoMajor == 1 {
		// An endpoint MUST NOT generate an HTTP/2 message containing connection-specific header fields.
		// Source: RFC7540.
		w.Header().Set("Connection", "keep-alive")
	}
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Cache-Control", "private, no-cache, no-store, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expire", "0")
	w.WriteHeader(http.StatusOK)

	rc := http.NewResponseController(w)

	for {
		select {
		case <-r.Context().Done():
			return
		case <-transport.disconnectCh:
			return
		case messages, messagesOK := <-transport.messages:
			if !messagesOK {
				return
			}
			_ = rc.SetWriteDeadline(time.Now().Add(streamWriteTimeout))
			for _, msg := range messages {
				_, err = w.Write(msg)
				if err != nil {
					return
				}
				_, err = w.Write([]byte("\n"))
				if err != nil {
					return
				}
			}
			_ = rc.Flush()
			_ = rc.SetWriteDeadline(time.Time{})
		}
	}
}
