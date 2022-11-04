package lnwire

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/stretchr/testify/require"
)

func hexToBytes(t *testing.T, hexStr string) []byte {
	t.Helper()

	decoded, err := hex.DecodeString(hexStr)
	require.NoError(t, err)

	return decoded
}

func hexToPubKey(t *testing.T, pkStr string) *btcec.PublicKey {
	t.Helper()

	pkBytes := hexToBytes(t, pkStr)
	pk, err := btcec.ParsePubKey(pkBytes)
	require.NoError(t, err)

	return pk
}

// TestKnownOpenChannel2Message tests decoding and encoding of an open_channel2
// wire message created by CLN.
//
// nolint:lll
func TestKnownOpenChannel2Message(t *testing.T) {
	t.Parallel()

	// Decode the known serialized message.
	knownEncodedMsg := hexToBytes(t, "004006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f2aa51d05d2a4cc27183fcdc3f78cb87812a617d8b843369e3c7bb51222898db200001d4c00001d4c00000000000186a00000000000000222ffffffffffffffff0000000000000000000501e30000006602324266de8403b3ab157a09f1f784d587af61831c998c151bcc21bb74c2b2314b02eb546006587442551b7f1c08e6336998d3ffafe1bedea92aaff9ba03bc3d02e6022dbc0053dd6f3310d84e55eebaacfad53fe3e3ec3c2cecb1cffebdd95fa8063f03b5aa92c890a616a425948f6eef8be810e7b65d1a6fe5bf5df62d83e1727f81d602346928c7642a1098a328e2787254c060f03a6b2c06af78a128868f913945d447029f443a7d1cb0f003caf78b9d5b7edef51fd7745b43a1b921b6f22ce748bfeb50010000")
	buf := bytes.NewBuffer(knownEncodedMsg)
	msg, err := ReadMessage(buf, 0)
	require.NoError(t, err, "failed to decode OpenChannel2")
	decoded, ok := msg.(*OpenChannel2)
	require.True(t, ok)

	// Verify the decoded message has the values we expect.
	expected := &OpenChannel2{
		FundingFeePerKWeight:  7500,
		CommitFeePerKWeight:   7500,
		FundingAmount:         100000,
		DustLimit:             546,
		MaxValueInFlight:      18446744073709551615,
		HtlcMinimum:           0,
		CsvDelay:              5,
		MaxAcceptedHTLCs:      483,
		LockTime:              102,
		FundingKey:            hexToPubKey(t, "02324266de8403b3ab157a09f1f784d587af61831c998c151bcc21bb74c2b2314b"),
		RevocationPoint:       hexToPubKey(t, "02eb546006587442551b7f1c08e6336998d3ffafe1bedea92aaff9ba03bc3d02e6"),
		PaymentPoint:          hexToPubKey(t, "022dbc0053dd6f3310d84e55eebaacfad53fe3e3ec3c2cecb1cffebdd95fa8063f"),
		DelayedPaymentPoint:   hexToPubKey(t, "03b5aa92c890a616a425948f6eef8be810e7b65d1a6fe5bf5df62d83e1727f81d6"),
		HtlcPoint:             hexToPubKey(t, "02346928c7642a1098a328e2787254c060f03a6b2c06af78a128868f913945d447"),
		FirstCommitmentPoint:  hexToPubKey(t, "029f443a7d1cb0f003caf78b9d5b7edef51fd7745b43a1b921b6f22ce748bfeb50"),
		ChannelFlags:          1,
		UpfrontShutdownScript: DeliveryAddress{},
		ExtraData:             ExtraOpaqueData{0x00, 0x00},
	}
	err = chainhash.Decode(&expected.ChainHash, "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")
	require.NoError(t, err)
	copy(expected.PendingChannelID[:], hexToBytes(t, "2aa51d05d2a4cc27183fcdc3f78cb87812a617d8b843369e3c7bb51222898db2"))

	require.Equal(t, expected, decoded)

	// Re-encode the message and verify it matches the original.
	buf = &bytes.Buffer{}
	_, err = WriteMessage(buf, decoded, 0)
	require.NoError(t, err, "failed to re-encode OpenChannel2")

	require.Equal(t, knownEncodedMsg, buf.Bytes())
}
