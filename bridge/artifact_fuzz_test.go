// SPDX-License-Identifier: MIT
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
	"testing"
)

func FuzzDeserializeArtifact(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("MKCKKSG2"))
	f.Add(make([]byte, 64))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		_, _ = deserializeEntry(nil, data)
	})
}

func FuzzArtifactEnvelopeWithValidChecksum(f *testing.F) {
	f.Add(uint8(kindPlaintext), "fingerprint", []byte("payload"))
	f.Fuzz(func(t *testing.T, kind uint8, fingerprint string, payload []byte) {
		if len(payload) > 1<<20 || len(fingerprint) > 128 {
			t.Skip()
		}
		artifact, err := wrapArtifact(objectKind(kind), fingerprint, payload)
		if err != nil {
			return
		}
		decodedKind, decodedFingerprint, decodedPayload, err := unwrapArtifact(artifact)
		if err != nil {
			t.Fatalf("freshly wrapped artifact was rejected: %v", err)
		}
		if decodedKind != objectKind(kind) || decodedFingerprint != fingerprint || string(decodedPayload) != string(payload) {
			t.Fatal("artifact envelope changed data")
		}
		artifact[len(artifact)-1] ^= 1
		if _, _, _, err = unwrapArtifact(artifact); err == nil {
			t.Fatal("checksum mutation was accepted")
		}
	})
}

func FuzzParameterLiteral(f *testing.F) {
	f.Add([]byte(`{"log_n":14,"log_slots":13,"q":[17],"p":[19,23],"scale":2,"sigma":3.2}`))
	f.Add([]byte(`{"log_n":14,"log_n":15}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		var dto parameterLiteralDTO
		_ = decodeParameterLiteral(data, &dto)
	})
}

func FuzzPlaintextPayload(f *testing.F) {
	ctx := testContext(f)
	values := [][]complex128{make([]complex128, ctx.params.Slots())}
	values[0][0] = 0.25 + 0.5i
	seed, err := writePlaintextPayload(encodeValues(ctx, values, 1, true))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 2<<20 {
			t.Skip()
		}
		_, _ = readPlaintextPayload(ctx, data)
	})
}

func FuzzCiphertextAndSharePayloads(f *testing.F) {
	ctx := testContext(f)
	party, err := generateParty(ctx, "fuzz-party")
	if err != nil {
		f.Fatal(err)
	}
	values := [][]complex128{make([]complex128, ctx.params.Slots())}
	values[0][0] = 0.25 + 0.5i
	ciphertext, err := encryptValues(ctx, party.pk, values, 1, true)
	if err != nil {
		f.Fatal(err)
	}
	share, err := partialDecrypt(party, ciphertext)
	if err != nil {
		f.Fatal(err)
	}
	cipherSeed, err := writeCipherPayload(ciphertext)
	if err != nil {
		f.Fatal(err)
	}
	shareSeed, err := writeSharePayload(share)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(uint8(0), cipherSeed)
	f.Add(uint8(1), shareSeed)
	f.Fuzz(func(t *testing.T, payloadKind uint8, data []byte) {
		if len(data) > 4<<20 {
			t.Skip()
		}
		if payloadKind&1 == 0 {
			_, _ = readCipherPayload(ctx, data)
		} else {
			_, _ = readSharePayload(ctx, data)
		}
	})
}

func FuzzCorrectnessTrackingPayloads(f *testing.F) {
	ctx := testContext(f)
	party, err := generateParty(ctx, "fuzz-tracking")
	if err != nil {
		f.Fatal(err)
	}
	values := [][]complex128{make([]complex128, ctx.params.Slots())}
	values[0][0] = 0.25 + 0.5i
	plaintext := encodeValues(ctx, values, 1, true)
	ciphertext, err := encryptValues(ctx, party.pk, values, 1, true)
	if err != nil {
		f.Fatal(err)
	}
	plainSeed, err := writePlaintextPayload(plaintext)
	if err != nil {
		f.Fatal(err)
	}
	cipherSeed, err := writeCipherPayload(ciphertext)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(uint8(0), math.Float64bits(plaintext.tracking.magnitudeBound), math.Float64bits(plaintext.tracking.errorBound), uint8(0))
	f.Add(uint8(1), math.Float64bits(ciphertext.tracking.magnitudeBound), math.Float64bits(ciphertext.tracking.errorBound), uint8(0))
	f.Add(uint8(1), math.Float64bits(math.Inf(1)), math.Float64bits(math.NaN()), uint8(2))
	f.Fuzz(func(t *testing.T, payloadKind uint8, magnitudeBits, errorBits uint64, status uint8) {
		var payload []byte
		var trackingOffset int
		if payloadKind&1 == 0 {
			payload = append([]byte(nil), plainSeed...)
			trackingOffset = 9 // chunk count (u64), complex flag (u8)
		} else {
			payload = append([]byte(nil), cipherSeed...)
			trackingOffset = 25 // length (u64), complex flag (u8), artifact ID (16 bytes)
		}
		binary.LittleEndian.PutUint64(payload[trackingOffset:], magnitudeBits)
		binary.LittleEndian.PutUint64(payload[trackingOffset+8:], errorBits)
		payload[trackingOffset+16] = status

		// Rewrap after mutation so the outer checksum remains valid and the
		// semantic payload decoder, not merely the checksum, judges the fields.
		kind := kindPlaintext
		if payloadKind&1 != 0 {
			kind = kindCiphertext
		}
		artifact, wrapErr := wrapArtifact(kind, ctx.fingerprint, payload)
		if wrapErr != nil {
			return
		}
		_, _, decoded, unwrapErr := unwrapArtifact(artifact)
		if unwrapErr != nil {
			t.Fatalf("checksum-preserving tracking mutation did not unwrap: %v", unwrapErr)
		}
		if payloadKind&1 == 0 {
			_, _ = readPlaintextPayload(ctx, decoded)
		} else {
			_, _ = readCipherPayload(ctx, decoded)
		}
	})
}

func FuzzChecksummedSemanticMutation(f *testing.F) {
	f.Add([]byte("native-payload"))
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > 1<<20 {
			t.Skip()
		}
		artifact, err := wrapArtifact(kindPlaintext, "f", payload)
		if err != nil {
			return
		}
		if len(payload) > 0 {
			body := artifact[:len(artifact)-sha256.Size]
			body[len(body)-1] ^= 1
			digest := sha256.Sum256(body)
			copy(artifact[len(body):], digest[:])
		}
		_, _, _, _ = unwrapArtifact(artifact)
	})
}

func FuzzPublicKeyPayload(f *testing.F) {
	ctx := testContext(f)
	party, err := generateParty(ctx, "fuzz-public-key")
	if err != nil {
		f.Fatal(err)
	}
	seed, err := writePublicKeyPayload(&nativePublicKey{ctx: ctx, pk: party.pk})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8<<20 {
			t.Skip()
		}
		_, _ = readPublicKeyPayload(ctx, data)
	})
}

func FuzzPrivatePartyPayload(f *testing.F) {
	ctx := testContext(f)
	party, err := generateParty(ctx, "fuzz-private-party")
	if err != nil {
		f.Fatal(err)
	}
	seed, err := writePartyPayload(party)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 16<<20 {
			t.Skip()
		}
		_, _ = readPartyPayload(ctx, data)
	})
}

func FuzzEvaluationKeyPayloads(f *testing.F) {
	ctx := testContext(f)
	party, err := generateParty(ctx, "fuzz-evaluation-key")
	if err != nil {
		f.Fatal(err)
	}
	contribution, err := generateEvalContribution(party, true, []int{1, 3}, true)
	if err != nil {
		f.Fatal(err)
	}
	keyset, err := combineEvalContributions([]*nativeEvalContribution{contribution})
	if err != nil {
		f.Fatal(err)
	}
	contributionSeed, _ := writeEvalContributionPayload(contribution)
	keysetSeed, _ := writeEvalSetPayload(keyset)
	f.Add(uint8(0), contributionSeed)
	f.Add(uint8(1), keysetSeed)
	f.Fuzz(func(t *testing.T, payloadKind uint8, data []byte) {
		if len(data) > 64<<20 {
			t.Skip()
		}
		if payloadKind&1 == 0 {
			_, _ = readEvalContributionPayload(ctx, data)
		} else {
			_, _ = readEvalSetPayload(ctx, data)
		}
	})
}

func FuzzRegistryHandleSequences(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 3})
	f.Fuzz(func(t *testing.T, operations []byte) {
		if len(operations) > 4096 {
			t.Skip()
		}
		handles := make([]uint64, 0)
		defer func() {
			for _, handle := range handles {
				_ = releaseObject(handle)
			}
		}()
		for _, operation := range operations {
			switch operation % 4 {
			case 0:
				handles = append(handles, putObject(kindContext, &nativeContext{}))
			case 1:
				if len(handles) != 0 {
					_, _ = getObject(handles[len(handles)-1], kindContext)
				}
			case 2:
				if len(handles) != 0 {
					_, _ = getObject(handles[len(handles)-1], kindCiphertext)
				}
			case 3:
				if len(handles) != 0 {
					_ = releaseObject(handles[len(handles)-1])
					handles = handles[:len(handles)-1]
				}
			}
		}
	})
}
