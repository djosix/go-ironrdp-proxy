package tpkt

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Action RDP PDU Action type
type Action int

const (
	ActionUnknown Action = iota
	ActionFastPath
	ActionX224 // TPKT/X.224
)

// PduInfo contains information about a detected PDU frame.
type PduInfo struct {
	Action Action
	Length int
}

const (
	// MinHeaderSize is the minimum bytes needed to determine the action.
	MinHeaderSize = 1
	// FastPathMinSize is the minimum bytes for a Fast-Path header.
	FastPathMinSize = 2
	// FastPathLargeSize is the bytes needed for a large Fast-Path length.
	FastPathLargeSize = 3
	// TPKTHeaderSize is the size of the TPKT header.
	TPKTHeaderSize = 4
)

var (
	// ErrInsufficientData indicates that the buffer does not contain enough data to determine the frame size.
	ErrInsufficientData = errors.New("insufficient data in buffer to determine frame size")
	// ErrInvalidAction indicates an unknown action code in the first byte.
	ErrInvalidAction = errors.New("invalid action code in header")
	// ErrInvalidLength indicates an issue parsing the length field.
	ErrInvalidLength = errors.New("invalid frame length parsed")
)

// FindPduSize attempts to find the total size and action of the next PDU
// based on the initial bytes in the provided buffer.
// It returns the PduInfo if successful.
// It returns ErrInsufficientData if more bytes are needed.
// It returns other errors for parsing failures.
func FindPduSize(buf []byte) (PduInfo, error) {
	if len(buf) < MinHeaderSize {
		return PduInfo{}, ErrInsufficientData
	}

	// [MS-RDPBCGR] 2.2.9.1.2 Fast-Path Output Header (TS_FP_OUTPUT_HEADER)
	// The action code is determined by the low 2 bits of the first byte.
	fpOutputHeader := buf[0]
	actionCode := fpOutputHeader & 0b11 // 0x03

	switch actionCode {
	case 0x00: // Fast-Path Action
		if len(buf) < FastPathMinSize {
			return PduInfo{}, ErrInsufficientData
		}
		a := buf[1]
		var length uint16
		if a&0x80 != 0 { // Check the high bit (most significant bit)
			// Length is encoded in 15 bits (lower 7 bits of 'a' and 8 bits of 'b')
			if len(buf) < FastPathLargeSize {
				return PduInfo{}, ErrInsufficientData
			}
			b := buf[2]
			length = (uint16(a&0x7F) << 8) | uint16(b)
		} else {
			// Length is encoded in 7 bits (lower 7 bits of 'a')
			length = uint16(a)
		}
		if length == 0 {
			// A zero length fast-path PDU is technically possible but often indicates an error or keep-alive.
			// Depending on the context, you might want to handle this specifically.
			// For now, treat it as potentially valid but return an error if strict parsing needed.
			// return PduInfo{}, fmt.Errorf("%w: fast-path length is zero", ErrInvalidLength)
			// Or allow it:
			return PduInfo{Action: ActionFastPath, Length: 0}, nil
		}
		return PduInfo{Action: ActionFastPath, Length: int(length)}, nil

	case 0x03: // X.224 Action (TPKT Header)
		// [MS-RDPBCGR] 2.2.1.1 TPKT Header (TPKT_HEADER)
		// Version (1 byte) = 0x03
		// Reserved (1 byte) = 0x00
		// Length (2 bytes, big-endian) - Includes header size
		if len(buf) < TPKTHeaderSize {
			return PduInfo{}, ErrInsufficientData
		}
		if buf[0] != 0x03 {
			// While the action code check already does this, double-check TPKT version.
			return PduInfo{}, fmt.Errorf("invalid TPKT header version: expected 0x03, got 0x%x", buf[0])
		}
		// Length is in bytes 2 and 3 (big-endian)
		length := binary.BigEndian.Uint16(buf[2:4])
		if length < TPKTHeaderSize {
			return PduInfo{}, fmt.Errorf("%w: TPKT length (%d) is smaller than header size (%d)", ErrInvalidLength, length, TPKTHeaderSize)
		}
		return PduInfo{Action: ActionX224, Length: int(length)}, nil

	default:
		return PduInfo{}, fmt.Errorf("%w: unknown action code %d (from header byte 0x%x)", ErrInvalidAction, actionCode, fpOutputHeader)
	}
}

// ReadFrame reads exactly one complete RDP frame from the provided reader.
// It reads only the bytes necessary to complete the frame without any extra bytes.
// Returns the complete frame data, the PDU action type, and any error encountered.
// If the reader returns io.EOF before a complete frame can be read, it returns io.ErrUnexpectedEOF.
func ReadFrame(reader io.Reader) ([]byte, Action, error) {
	// First, read the minimum number of bytes to determine action type
	headerBuf := make([]byte, MinHeaderSize)
	if _, err := io.ReadFull(reader, headerBuf); err != nil {
		if err == io.EOF {
			return nil, ActionUnknown, io.ErrUnexpectedEOF
		}
		return nil, ActionUnknown, err
	}

	// Based on the first byte, determine how many more bytes we need for the header
	fpOutputHeader := headerBuf[0]
	actionCode := fpOutputHeader & 0b11 // 0x03

	var additionalBytes int
	var frameBuffer []byte

	switch actionCode {
	case 0x00: // Fast-Path Action
		// Need at least one more byte for minimal fast-path header
		additionalBytes = FastPathMinSize - MinHeaderSize
		headerExtension := make([]byte, additionalBytes)
		if _, err := io.ReadFull(reader, headerExtension); err != nil {
			if err == io.EOF {
				return nil, ActionUnknown, io.ErrUnexpectedEOF
			}
			return nil, ActionUnknown, err
		}

		// Combine the initial header with the extension
		headerBuf = append(headerBuf, headerExtension...)

		// Check if we need another byte for large size format
		a := headerBuf[1]
		if a&0x80 != 0 { // Check the high bit (most significant bit)
			// Need one more byte for the extended length
			lengthExtension := make([]byte, 1)
			if _, err := io.ReadFull(reader, lengthExtension); err != nil {
				if err == io.EOF {
					return nil, ActionUnknown, io.ErrUnexpectedEOF
				}
				return nil, ActionUnknown, err
			}
			headerBuf = append(headerBuf, lengthExtension...)
		}

		// Now we have the complete header, determine the PDU size
		pduInfo, err := FindPduSize(headerBuf)
		if err != nil {
			return nil, ActionUnknown, fmt.Errorf("failed to parse Fast-Path header: %w", err)
		}

		// Read the rest of the frame (payload)
		// Note: The length in pduInfo is the payload length, and we already have the header
		frameBuffer = make([]byte, pduInfo.Length)
		if _, err := io.ReadFull(reader, frameBuffer); err != nil {
			if err == io.EOF {
				return nil, ActionUnknown, io.ErrUnexpectedEOF
			}
			return nil, ActionUnknown, err
		}

		// Combine header and payload
		completeFrame := append(headerBuf, frameBuffer...)
		return completeFrame, ActionFastPath, nil

	case 0x03: // X.224 Action (TPKT Header)
		// Need the remaining TPKT header bytes
		additionalBytes = TPKTHeaderSize - MinHeaderSize
		headerExtension := make([]byte, additionalBytes)
		if _, err := io.ReadFull(reader, headerExtension); err != nil {
			if err == io.EOF {
				return nil, ActionUnknown, io.ErrUnexpectedEOF
			}
			return nil, ActionUnknown, err
		}

		// Combine the initial header with the extension
		headerBuf = append(headerBuf, headerExtension...)

		// Parse the complete TPKT header
		pduInfo, err := FindPduSize(headerBuf)
		if err != nil {
			return nil, ActionUnknown, fmt.Errorf("failed to parse TPKT header: %w", err)
		}

		// Read the rest of the frame (payload)
		// Note: pduInfo.Length includes the header, so subtract to get payload size
		payloadSize := pduInfo.Length - TPKTHeaderSize
		if payloadSize < 0 {
			return nil, ActionUnknown, errors.New("invalid TPKT payload size calculated")
		}

		frameBuffer = make([]byte, payloadSize)
		if payloadSize > 0 {
			if _, err := io.ReadFull(reader, frameBuffer); err != nil {
				if err == io.EOF {
					return nil, ActionUnknown, io.ErrUnexpectedEOF
				}
				return nil, ActionUnknown, err
			}
		}

		// Combine header and payload
		completeFrame := append(headerBuf, frameBuffer...)
		return completeFrame, ActionX224, nil

	default:
		return nil, ActionUnknown, fmt.Errorf("%w: unknown action code %d (from header byte 0x%x)",
			ErrInvalidAction, actionCode, fpOutputHeader)
	}
}
