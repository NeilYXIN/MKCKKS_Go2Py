// SPDX-License-Identifier: MIT
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
	"testing"
)

// mutateSerializedSeed applies bounded structural mutations to a valid native
// payload. Large []byte fuzz arguments can outgrow Go's fixed fuzz-worker
// shared-memory transport before the target callback can reject them. Keeping
// the valid payload in the target closure and fuzzing only fixed-width mutation
// instructions reaches the semantic decoders without that framework failure.
func mutateSerializedSeed(seed []byte, mutation uint8, offset, value uint64, span uint16) []byte {
	data := append([]byte(nil), seed...)
	switch mutation % 7 {
	case 0: // Preserve a valid payload.
		return data
	case 1: // Overwrite one byte.
		if len(data) == 0 {
			return []byte{byte(value)}
		}
		data[int(offset%uint64(len(data)))] = byte(value)
	case 2: // Overwrite a complete fixed-width field.
		if len(data) < 8 {
			return data[:0]
		}
		position := int(offset % uint64(len(data)-7))
		binary.LittleEndian.PutUint64(data[position:], value)
	case 3: // Truncate at any boundary, including zero or the full length.
		return data[:int(offset%uint64(len(data)+1))]
	case 4: // Delete a bounded range.
		if len(data) == 0 {
			return data
		}
		position := int(offset % uint64(len(data)))
		count := 1 + int(span%256)
		if remaining := len(data) - position; count > remaining {
			count = remaining
		}
		copy(data[position:], data[position+count:])
		data = data[:len(data)-count]
	case 5: // Insert a bounded constant range.
		position := int(offset % uint64(len(data)+1))
		count := 1 + int(span%256)
		originalLength := len(data)
		data = append(data, make([]byte, count)...)
		copy(data[position+count:], data[position:originalLength])
		for index := position; index < position+count; index++ {
			data[index] = byte(value)
		}
	case 6: // XOR a bounded range without changing its size.
		if len(data) == 0 {
			return data
		}
		position := int(offset % uint64(len(data)))
		count := 1 + int(span%256)
		if remaining := len(data) - position; count > remaining {
			count = remaining
		}
		for index := position; index < position+count; index++ {
			data[index] ^= byte(value)
		}
	}
	return data
}

func TestMutateSerializedSeedBounded(t *testing.T) {
	seed := make([]byte, 512)
	for index := range seed {
		seed[index] = byte(index)
	}
	original := string(seed)
	tests := []struct {
		name        string
		mutation    uint8
		offset      uint64
		value       uint64
		span        uint16
		expectedLen int
	}{
		{name: "unchanged", mutation: 0, expectedLen: 512},
		{name: "byte", mutation: 1, offset: 10, value: 0xff, expectedLen: 512},
		{name: "uint64", mutation: 2, offset: 10, value: math.MaxUint64, expectedLen: 512},
		{name: "truncate", mutation: 3, offset: 17, expectedLen: 17},
		{name: "delete", mutation: 4, offset: 10, span: 9, expectedLen: 502},
		{name: "insert", mutation: 5, offset: 10, value: 0xa5, span: 9, expectedLen: 522},
		{name: "xor", mutation: 6, offset: 10, value: 0xff, span: 9, expectedLen: 512},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mutated := mutateSerializedSeed(
				seed,
				test.mutation,
				test.offset,
				test.value,
				test.span,
			)
			if len(mutated) != test.expectedLen {
				t.Fatalf("length=%d, want %d", len(mutated), test.expectedLen)
			}
			if len(mutated) > len(seed)+256 {
				t.Fatalf("bounded mutation grew from %d to %d bytes", len(seed), len(mutated))
			}
			if string(seed) != original {
				t.Fatal("mutation changed its seed")
			}
		})
	}
	for mutation := uint8(0); mutation < 7; mutation++ {
		if mutated := mutateSerializedSeed(nil, mutation, 0, 0, math.MaxUint16); len(mutated) > 256 {
			t.Fatalf("empty-seed mutation %d produced %d bytes", mutation, len(mutated))
		}
	}
}

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
	f.Add(uint8(0), uint64(0), uint64(0), uint16(0))
	f.Add(uint8(2), uint64(0), uint64(math.MaxUint64), uint16(0))
	f.Fuzz(func(t *testing.T, mutation uint8, offset, value uint64, span uint16) {
		data := mutateSerializedSeed(seed, mutation, offset, value, span)
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
	f.Add(uint8(0), uint8(0), uint64(0), uint64(0), uint16(0))
	f.Add(uint8(1), uint8(0), uint64(0), uint64(0), uint16(0))
	f.Add(uint8(0), uint8(2), uint64(0), uint64(math.MaxUint64), uint16(0))
	f.Fuzz(func(t *testing.T, payloadKind, mutation uint8, offset, value uint64, span uint16) {
		if payloadKind&1 == 0 {
			data := mutateSerializedSeed(cipherSeed, mutation, offset, value, span)
			_, _ = readCipherPayload(ctx, data)
		} else {
			data := mutateSerializedSeed(shareSeed, mutation, offset, value, span)
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
	f.Add(uint8(0), uint64(0), uint64(0), uint16(0))
	f.Add(uint8(2), uint64(0), uint64(math.MaxUint64), uint16(0))
	f.Fuzz(func(t *testing.T, mutation uint8, offset, value uint64, span uint16) {
		data := mutateSerializedSeed(seed, mutation, offset, value, span)
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
	f.Add(uint8(0), uint64(0), uint64(0), uint16(0))
	f.Add(uint8(2), uint64(0), uint64(math.MaxUint64), uint16(0))
	f.Fuzz(func(t *testing.T, mutation uint8, offset, value uint64, span uint16) {
		data := mutateSerializedSeed(seed, mutation, offset, value, span)
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
	f.Add(uint8(0), uint8(0), uint64(0), uint64(0), uint16(0))
	f.Add(uint8(1), uint8(0), uint64(0), uint64(0), uint16(0))
	f.Add(uint8(0), uint8(2), uint64(0), uint64(math.MaxUint64), uint16(0))
	f.Fuzz(func(t *testing.T, payloadKind, mutation uint8, offset, value uint64, span uint16) {
		if payloadKind&1 == 0 {
			data := mutateSerializedSeed(contributionSeed, mutation, offset, value, span)
			_, _ = readEvalContributionPayload(ctx, data)
		} else {
			data := mutateSerializedSeed(keysetSeed, mutation, offset, value, span)
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
