package proxy

import (
	"io"

	"github.com/gorilla/websocket"
)

// wsReadWriteCloser implements io.ReadWriteCloser for a WebSocket connection.
type wsReadWriteCloser struct {
	ws *websocket.Conn
	r  io.Reader
}

func newWsReadWriteCloser(ws *websocket.Conn) *wsReadWriteCloser {
	return &wsReadWriteCloser{
		ws: ws,
		r:  websocket.JoinMessages(ws, ""),
	}
}

func (w *wsReadWriteCloser) Read(p []byte) (int, error) {
	return w.r.Read(p)
}

func (w *wsReadWriteCloser) Write(p []byte) (int, error) {
	return len(p), w.ws.WriteMessage(websocket.BinaryMessage, p)
}

func (w *wsReadWriteCloser) Close() error {
	return w.ws.Close()
}
