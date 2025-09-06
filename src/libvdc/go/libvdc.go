package libvdc

import (
	"errors"
	"github.com/fxamacker/cbor/v2"
)

var magic = []byte{0x89, 'v', 'd', 'c', 0x0d, 0x0a, 0x1a, 0x0a}

type VdcInfo struct {
	Meta     map[int]any
	Payloads []map[int]any
	Receipts [][]byte
	Anchors  []map[int]any
	Times    []map[int]any
}

type vdcBody struct {
	_ struct{} `cbor:"toarray"`
	Magic    []byte            `cbor:"1,keyasint,omitempty"`
	Meta     map[int]any       `cbor:"2,keyasint,omitempty"`
	Payloads []map[int]any     `cbor:"3,keyasint,omitempty"`
	Receipts [][]byte          `cbor:"4,keyasint,omitempty"`
	Anchors  []map[int]any     `cbor:"5,keyasint,omitempty"`
	Times    []map[int]any     `cbor:"6,keyasint,omitempty"`
}

func ParseVDC(buf []byte) (*VdcInfo, error) {
	if len(buf) < len(magic) || string(buf[:len(magic)]) != string(magic) {
		return nil, errors.New("not a VDC file")
	}
	var body vdcBody
	if err := cbor.Unmarshal(buf[len(magic):], &body); err != nil {
		return nil, err
	}
	return &VdcInfo{Meta: body.Meta, Payloads: body.Payloads, Receipts: body.Receipts, Anchors: body.Anchors, Times: body.Times}, nil
}
