package main

import (
	"log"
	"net/http"

	"github.com/djosix/IronRDP-Proxy-Go/internal/proxy"
	"github.com/gorilla/websocket"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./web/index.html")
	})

	http.HandleFunc("/iron-remote-gui.js", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./web/node_modules/@devolutions/iron-remote-gui/iron-remote-gui.js")
	})

	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{}

		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println(err)
			return
		}
		defer ws.Close()

		proxy.Handle(r.Context(), ws)
	})

	addr := ":4567"
	log.Println("Listening on", addr)
	http.ListenAndServe(addr, nil)
}
