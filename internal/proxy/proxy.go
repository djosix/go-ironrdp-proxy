package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"

	"github.com/djosix/IronRDP-Proxy-Go/internal/rdcleanpath"
	"github.com/djosix/IronRDP-Proxy-Go/internal/tpkt"
	"github.com/gorilla/websocket"
	"golang.org/x/sync/errgroup"
)

func Handle(ctx context.Context, ws *websocket.Conn) error {
	rdpClientConn := newWsReadWriteCloser(ws)

	// Read RCCleanPath request from client
	var cleanPathReq *rdcleanpath.Pdu
	{
		frame, _, err := tpkt.ReadFrame(rdpClientConn)
		if err != nil {
			return fmt.Errorf("read frame: %v", err)
		}
		pdu, err := rdcleanpath.Unmarshal(frame)
		if err != nil {
			return fmt.Errorf("decode rdcleanpath pdu: %v", err)
		}
		cleanPathReq = pdu
	}

	rdpServerConn, err := net.Dial("tcp", cleanPathReq.Destination)
	if err != nil {
		return fmt.Errorf("dial server: %v", err)
	}

	// Write X224 connection PDU to server
	if _, err := rdpServerConn.Write(
		append([]byte(cleanPathReq.PreconnectionBlob), cleanPathReq.X224ConnectionPdu...),
	); err != nil {
		return fmt.Errorf("conn write: %v", err)
	}

	// Read X224 connection PDU from server
	x224Resp, _, err := tpkt.ReadFrame(rdpServerConn)
	if err != nil {
		return fmt.Errorf("conn read: %v", err)
	}

	// Upgrade connection to TLS and collect certificate chain
	certChain := [][]byte{}
	{
		tlsConn := tls.Client(rdpServerConn, &tls.Config{
			InsecureSkipVerify: true,
			MaxVersion:         tls.VersionTLS12, // Works with most Windows
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return fmt.Errorf("tls server: %v", err)
		}
		peerCertificates := tlsConn.ConnectionState().PeerCertificates
		if len(peerCertificates) == 0 {
			return fmt.Errorf("no peer certificates found")
		}
		for _, cert := range peerCertificates {
			certChain = append(certChain, cert.Raw)
		}
		// Upgrade connection to TLS
		rdpServerConn = tlsConn
	}

	// Write RCCleanPath response to client
	{
		cleanPathResp, err := rdcleanpath.NewResp(rdpServerConn.RemoteAddr().String(), x224Resp, certChain)
		if err != nil {
			return fmt.Errorf("rdcleanpath new resp: %v", err)
		}

		cleanPathRespDer, err := cleanPathResp.Marshal()
		if err != nil {
			return fmt.Errorf("rdcleanpath marshal: %v", err)
		}

		if _, err := rdpClientConn.Write(cleanPathRespDer); err != nil {
			return fmt.Errorf("write message: %v", err)
		}
	}

	// Handle bidirectional communication
	group, ctx := errgroup.WithContext(ctx)
	group.Go(func() error {
		_, err := io.Copy(rdpServerConn, rdpClientConn)
		return err
	})
	group.Go(func() error {
		_, err := io.Copy(rdpClientConn, rdpServerConn)
		return err
	})
	group.Go(func() error {
		<-ctx.Done()
		rdpClientConn.Close()
		rdpServerConn.Close()
		return nil
	})
	return group.Wait()
}
