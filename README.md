## IronRDP Proxy written in Go

Simple Go proxy implementation for the IronRDP web client.

**Key Points:**

* Go backend for the Rust WASM IronRDP web client.
* Enables web-based RDP access.
* Implemented the RDCleanPath and TPKT protocols.

**Usage:**

1.  `cd web && npm install` (Install `iron-remote-gui.js`)
2.  `go run main.go` (Run the proxy server)
3.  Open `http://localhost:4567` in your browser.

**Demo:**

[![IronRDP Demo Video](https://img.youtube.com/vi/alUd40hWlTo/0.jpg)](https://www.youtube.com/watch?v=alUd40hWlTo)

**References:**

* https://github.com/Devolutions/IronRDP/blob/570cbe3c3f6dcbda67334771202ac60f44a36285/crates/ironrdp-web/src/session.rs
* https://github.com/Devolutions/devolutions-gateway/blob/ed3ac91fe2f8548153ab1c0ed59c7467da21d944/devolutions-gateway/src/rdp_extension.rs
