package lnwire

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRemoteSigsFirstEncodeDecode tests that we're able to properly encode and
// decode the RemoteSigsFirst bool within TLV streams.
func TestRemoteSigsFirstEncodeDecode(t *testing.T) {
	t.Parallel()

	remoteSigsFirst := RemoteSigsFirst(true)
	var extraData ExtraOpaqueData
	require.NoError(t, extraData.PackRecords(&remoteSigsFirst))

	// The encoded TLV should have length 0.
	require.Equal(t, extraData, ExtraOpaqueData([]byte{0x04, 0x00}))

	var remoteSigsFirst2 RemoteSigsFirst
	tlvs, err := extraData.ExtractRecords(&remoteSigsFirst2)
	require.NoError(t, err)

	require.Contains(t, tlvs, RemoteSigsFirstRecordType)
	require.Equal(t, remoteSigsFirst, remoteSigsFirst2)
}

// TestRemoteSigsFirstEncodeError tests that attempting to encode a value of
// false returns an error. Since RemoteSigsFirst has no data associated with it,
// we should only ever encode it with a value of true.
func TestRemoteSigsFirstEncodeError(t *testing.T) {
	t.Parallel()

	remoteSigsFirst := RemoteSigsFirst(false)
	var extraData ExtraOpaqueData
	require.Error(t, extraData.PackRecords(&remoteSigsFirst))
}

// TestRemoteSigsFirstDecodeError tests that attempting to decode a TLV with
// non-zero length returns an error. Since RemoteSigsFirst has no data
// associated with it, it should only ever be encoded with a value of true.
func TestRemoteSigsFirstDecodeError(t *testing.T) {
	t.Parallel()

	extraData := ExtraOpaqueData([]byte{0x04, 0x01, 0x00})
	var remoteSigsFirst RemoteSigsFirst
	_, err := extraData.ExtractRecords(&remoteSigsFirst)
	require.Error(t, err)
}
