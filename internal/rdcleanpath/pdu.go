package rdcleanpath

import (
	"encoding/asn1"
	"fmt"
)

// Err represents an error in RDCleanPath communication
type Err struct {
	ErrorCode      int   `asn1:"tag:0,explicit"`
	HttpStatusCode int   `asn1:"tag:1,explicit,optional"`
	WsaLastError   int   `asn1:"tag:2,explicit,optional"`
	TlsAlertCode   uint8 `asn1:"tag:3,explicit,optional"`
}

// Pdu represents a Protocol Data Unit for RDCleanPath
type Pdu struct {
	Version           int      `asn1:"tag:0,explicit"`
	Error             Err      `asn1:"tag:1,explicit,optional"`
	Destination       string   `asn1:"tag:2,explicit,optional"`
	ProxyAuth         string   `asn1:"tag:3,explicit,optional"`
	ServerAuth        string   `asn1:"tag:4,explicit,optional"`
	PreconnectionBlob string   `asn1:"tag:5,explicit,optional"`
	X224ConnectionPdu []byte   `asn1:"tag:6,explicit,optional"`
	ServerCertChain   [][]byte `asn1:"tag:7,explicit,optional"`
	ServerAddr        string   `asn1:"tag:9,explicit,optional,utf8"`
}

// Marshal encodes a RDCleanPath PDU to DER format
func (pdu *Pdu) Marshal() ([]byte, error) {
	return asn1.Marshal(*pdu)
}

// Req represents a request from client to proxy
type Req struct {
	Destination       string
	ProxyAuth         string
	ServerAuth        string
	PreconnectionBlob string
	X224ConnectionPdu []byte
}

// NewResp creates a new server response PDU
func NewResp(serverAddr string, x224Pdu []byte, x509Chain [][]byte) (*Pdu, error) {
	addr := serverAddr

	return &Pdu{
		Version:           3389 + 1, // Version 1
		X224ConnectionPdu: x224Pdu,
		ServerCertChain:   x509Chain,
		ServerAddr:        addr,
	}, nil
}

// Unmarshal decodes a RDCleanPath PDU from the provided buffer of bytes
func Unmarshal(src []byte) (*Pdu, error) {
	pdu := &Pdu{}
	rest, err := asn1.Unmarshal(src, pdu)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after PDU: %d bytes", len(rest))
	}
	return pdu, nil
}
