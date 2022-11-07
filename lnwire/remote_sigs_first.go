package lnwire

import (
	"io"

	"github.com/lightningnetwork/lnd/tlv"
)

const (
	// RemoteSigsFirstRecordType is the TLV record type that indicates the
	// non-initiator of a dual funded channel must send their funding
	// transaction signatures first.
	//
	// There is no data associated with this TLV. The mere presence of the
	// TLV indicates that the non-initiator goes first.
	RemoteSigsFirstRecordType tlv.Type = 4
)

// RemoteSigsFirst indicates the non-initiator of a dual funded channel must
// send their funding transaction signatures first.
type RemoteSigsFirst bool

// Record returns a TLV record that can be used to encode/decode the
// RemoteSigsFirst type within a TLV stream.
func (r *RemoteSigsFirst) Record() tlv.Record {
	return tlv.MakeStaticRecord(RemoteSigsFirstRecordType, r, 0,
		remoteSigsFirstEncoder, remoteSigsFirstDecoder,
	)
}

// remoteSigsFirstEncoder is a custom TLV encoder for the RemoteSigsFirst
// record.
func remoteSigsFirstEncoder(w io.Writer, val interface{}, buf *[8]byte) error {
	if v, ok := val.(*RemoteSigsFirst); ok && bool(*v) {
		// There is no data associated with this TLV, so we do nothing.
		return nil
	}

	return tlv.NewTypeForEncodingErr(val, "lnwire.RemoteSigsFirst")
}

// remoteSigsFirstDecoder is a custom TLV decoder for the RemoteSigsFirst
// record.
func remoteSigsFirstDecoder(r io.Reader, val interface{}, buf *[8]byte,
	l uint64) error {

	if v, ok := val.(*RemoteSigsFirst); ok && l == 0 {
		// There is no data associated with this TLV. It's mere presence
		// indicates the val should be true.
		*v = true
		return nil
	}

	return tlv.NewTypeForEncodingErr(val, "lnwire.RemoteSigsFirst")
}
