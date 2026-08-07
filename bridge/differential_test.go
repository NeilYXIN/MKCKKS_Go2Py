// SPDX-License-Identifier: MIT
package main

import (
	"encoding/json"
	"fmt"
	"math"
	"math/cmplx"
	"math/rand"
	"os"
	"reflect"
	"sort"
	"strconv"
	"testing"

	"github.com/ldsec/lattigo/v2/ckks"
	"mk-lattigo/mkckks"
	"mk-lattigo/mkrlwe"
)

func differentialContext(t testing.TB, preset string) *nativeContext {
	t.Helper()
	dto := parameterLiteralDTO{
		LogN: 14, LogSlots: 13,
		Q:     []uint64{0x7ffffffffe70001, 0xffffffff00001, 0xfffffffe40001, 0xfffffffe20001, 0xfffffffbe0001, 0xfffffffa60001},
		P:     []uint64{0xffffffffffc0001, 0xfffffffff840001},
		Scale: 1 << 52, Sigma: 3.2,
	}
	if preset == "PN15QP880" {
		dto = parameterLiteralDTO{
			LogN: 15, LogSlots: 14,
			Q: []uint64{
				0xfffffffff6a0001, 0x3fffffffd60001, 0x3fffffffca0001,
				0x3fffffff6d0001, 0x3fffffff5d0001, 0x3fffffff550001,
				0x3fffffff390001, 0x3fffffff360001, 0x3fffffff2a0001,
				0x3fffffff000001, 0x3ffffffefa0001, 0x3ffffffef40001,
				0x3ffffffed70001, 0x3ffffffed30001,
			},
			P: []uint64{0x7ffffffffe70001, 0x7ffffffffe10001}, Scale: 1 << 54, Sigma: 3.2,
		}
	}
	raw, err := json.Marshal(dto)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := newContext(raw, 1)
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

func fullDecrypt(t testing.TB, ciphertext *nativeCiphertext, parties ...*nativeParty) []complex128 {
	t.Helper()
	keys := mkrlwe.NewSecretKeySet()
	for _, party := range parties {
		keys.AddSecretKey(party.sk)
	}
	values := make([]complex128, 0, len(ciphertext.chunks)*ciphertext.ctx.params.Slots())
	for _, chunk := range ciphertext.chunks {
		message := mkckks.NewDecryptor(ciphertext.ctx.params).Decrypt(chunk, keys)
		values = append(values, message.Value...)
	}
	return values[:ciphertext.length]
}

func assertPrecision(t testing.TB, params *nativeContext, got, want []complex128, slack int) {
	t.Helper()
	bound := primitivePrecisionBound(params, params.params.Scale(), slack)
	assertPrecisionBound(t, got, want, bound)
}

func primitivePrecisionBound(params *nativeContext, scale float64, slack int) float64 {
	return math.Exp2(-math.Log2(scale) + float64(params.params.LogSlots()) + float64(slack))
}

func assertPrecisionBound(t testing.TB, got, want []complex128, bound float64) {
	t.Helper()
	if err := comparePrecisionBound(got, want, bound); err != nil {
		t.Fatal(err)
	}
}

func comparePrecisionBound(got, want []complex128, bound float64) error {
	if bound < 0 || math.IsNaN(bound) || math.IsInf(bound, 0) {
		return fmt.Errorf("precision bound must be finite and non-negative: %.17g", bound)
	}
	if len(got) != len(want) {
		return fmt.Errorf("value length differs: got=%d want=%d", len(got), len(want))
	}
	for index := range want {
		delta := got[index] - want[index]
		if math.Abs(real(delta)) > bound || math.Abs(imag(delta)) > bound {
			return fmt.Errorf("slot %d error %v exceeds %.3e (got %v want %v)", index, delta, bound, got[index], want[index])
		}
	}
	return nil
}

func maximumMagnitude(values []complex128) float64 {
	maximum := 0.0
	for _, value := range values {
		if magnitude := cmplx.Abs(value); magnitude > maximum {
			maximum = magnitude
		}
	}
	return maximum
}

func productPrecisionBound(
	params *nativeContext,
	result *mkckks.Ciphertext,
	left, right []complex128,
	leftError, rightError float64,
) float64 {
	return maximumMagnitude(right)*leftError +
		maximumMagnitude(left)*rightError +
		leftError*rightError +
		primitivePrecisionBound(params, result.Scale, 12)
}

func assertCipherMetadata(t testing.TB, bridge *nativeCiphertext, direct []*mkckks.Ciphertext, complexValues bool) {
	t.Helper()
	if err := compareCipherMetadata(bridge, direct, complexValues); err != nil {
		t.Fatal(err)
	}
}

func compareCipherMetadata(bridge *nativeCiphertext, direct []*mkckks.Ciphertext, complexValues bool) error {
	if len(bridge.chunks) != len(direct) {
		return fmt.Errorf("chunk count differs: bridge=%d direct=%d", len(bridge.chunks), len(direct))
	}
	if bridge.isComplex != complexValues {
		return fmt.Errorf("complex metadata differs: bridge=%t expected=%t", bridge.isComplex, complexValues)
	}
	for index := range direct {
		if bridge.chunks[index].Level() != direct[index].Level() {
			return fmt.Errorf("chunk %d level differs: bridge=%d direct=%d", index, bridge.chunks[index].Level(), direct[index].Level())
		}
		if bridge.chunks[index].Scale != direct[index].Scale {
			return fmt.Errorf("chunk %d scale differs: bridge=%.17g direct=%.17g", index, bridge.chunks[index].Scale, direct[index].Scale)
		}
		bridgeIDs := make([]string, 0, bridge.chunks[index].IDSet().Size())
		directIDs := make([]string, 0, direct[index].IDSet().Size())
		for id := range bridge.chunks[index].IDSet().Value {
			bridgeIDs = append(bridgeIDs, id)
		}
		for id := range direct[index].IDSet().Value {
			directIDs = append(directIDs, id)
		}
		sort.Strings(bridgeIDs)
		sort.Strings(directIDs)
		if !reflect.DeepEqual(bridgeIDs, directIDs) {
			return fmt.Errorf("chunk %d participants differ: bridge=%v direct=%v", index, bridgeIDs, directIDs)
		}
	}
	return nil
}

func compareCorrectnessTracking(got, want correctnessTracking) error {
	if got.magnitudeBound != want.magnitudeBound {
		return fmt.Errorf("tracked magnitude differs: got=%.17g want=%.17g", got.magnitudeBound, want.magnitudeBound)
	}
	if got.errorBound != want.errorBound {
		return fmt.Errorf("tracked error differs: got=%.17g want=%.17g", got.errorBound, want.errorBound)
	}
	if got.rangeExceeded != want.rangeExceeded {
		return fmt.Errorf("tracked range status differs: got=%t want=%t", got.rangeExceeded, want.rangeExceeded)
	}
	return nil
}

func TestDifferentialComparatorSensitivity(t *testing.T) {
	ctx := differentialContext(t, "PN14QP439")
	party, err := generateParty(ctx, "comparator-alice")
	if err != nil {
		t.Fatal(err)
	}
	values := make([]complex128, ctx.params.Slots())
	values[0] = 0.25 + 0.125i
	bridge, err := encryptValues(ctx, party.pk, [][]complex128{values}, 1, true)
	if err != nil {
		t.Fatal(err)
	}
	direct := bridge.chunks[0].CopyNew()

	if err = compareCipherMetadata(bridge, []*mkckks.Ciphertext{direct}, true); err != nil {
		t.Fatalf("valid metadata rejected: %v", err)
	}
	if err = comparePrecisionBound([]complex128{values[0]}, []complex128{values[0]}, 0); err != nil {
		t.Fatalf("valid exact comparison rejected: %v", err)
	}

	perturbedScale := direct.CopyNew()
	perturbedScale.Scale *= 2
	if compareCipherMetadata(bridge, []*mkckks.Ciphertext{perturbedScale}, true) == nil {
		t.Fatal("scale perturbation was not detected")
	}
	perturbedLevel := mkckks.NewEvaluator(ctx.params).DropLevelNew(direct, 1)
	if compareCipherMetadata(bridge, []*mkckks.Ciphertext{perturbedLevel}, true) == nil {
		t.Fatal("level perturbation was not detected")
	}
	bob, err := generateParty(ctx, "comparator-bob")
	if err != nil {
		t.Fatal(err)
	}
	bobCipher, err := encryptValues(ctx, bob.pk, [][]complex128{values}, 1, true)
	if err != nil {
		t.Fatal(err)
	}
	if compareCipherMetadata(bridge, bobCipher.chunks, true) == nil {
		t.Fatal("participant perturbation was not detected")
	}
	if compareCipherMetadata(bridge, []*mkckks.Ciphertext{direct}, false) == nil {
		t.Fatal("complexity perturbation was not detected")
	}
	if compareCipherMetadata(bridge, []*mkckks.Ciphertext{direct, direct.CopyNew()}, true) == nil {
		t.Fatal("chunk-count perturbation was not detected")
	}
	if comparePrecisionBound([]complex128{values[0] + 1}, []complex128{values[0]}, 0.5) == nil {
		t.Fatal("value perturbation was not detected")
	}
	if comparePrecisionBound([]complex128{values[0]}, []complex128{values[0]}, math.Inf(1)) == nil {
		t.Fatal("infinite precision bound was accepted")
	}

	wantTracking := bridge.tracking
	perturbedTracking := wantTracking
	perturbedTracking.magnitudeBound = math.Nextafter(perturbedTracking.magnitudeBound, math.Inf(1))
	if compareCorrectnessTracking(perturbedTracking, wantTracking) == nil {
		t.Fatal("magnitude-bound perturbation was not detected")
	}
	perturbedTracking = wantTracking
	perturbedTracking.errorBound = math.Nextafter(perturbedTracking.errorBound, math.Inf(1))
	if compareCorrectnessTracking(perturbedTracking, wantTracking) == nil {
		t.Fatal("error-bound perturbation was not detected")
	}
	perturbedTracking = wantTracking
	perturbedTracking.rangeExceeded = !perturbedTracking.rangeExceeded
	if compareCorrectnessTracking(perturbedTracking, wantTracking) == nil {
		t.Fatal("range-status perturbation was not detected")
	}
}

func wrapDirect(ctx *nativeContext, chunks []*mkckks.Ciphertext, length int, complexValues bool) *nativeCiphertext {
	return &nativeCiphertext{ctx: ctx, chunks: chunks, length: length, isComplex: complexValues}
}

func directEncode(ctx *nativeContext, values []complex128, level int, scale float64) *ckks.Plaintext {
	params, err := ckks.NewParameters(ctx.params.Parameters.Parameters, ctx.params.LogSlots(), scale)
	if err != nil {
		panic(err)
	}
	plaintext := ckks.NewPlaintext(params, level, scale)
	ckks.NewEncoder(params).Encode(plaintext, values, ctx.params.LogSlots())
	return plaintext
}

func directAddPlaintext(ctx *nativeContext, input *mkckks.Ciphertext, values []complex128, subtract bool) *mkckks.Ciphertext {
	result := input.CopyNew()
	plaintext := directEncode(ctx, values, input.Level(), input.Scale)
	if subtract {
		ctx.params.RingQ().SubLvl(input.Level(), result.Value["0"], plaintext.Value, result.Value["0"])
	} else {
		ctx.params.RingQ().AddLvl(input.Level(), result.Value["0"], plaintext.Value, result.Value["0"])
	}
	return result
}

func repeated(values []complex128, value complex128) []complex128 {
	result := make([]complex128, len(values))
	for index := range result {
		result[index] = value
	}
	return result
}

func testDifferentialOperations(t *testing.T, preset string) {
	ctx := differentialContext(t, preset)
	evaluator := mkckks.NewEvaluator(ctx.params)
	alice, err := generateParty(ctx, "differential-alice")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := generateParty(ctx, "differential-bob")
	if err != nil {
		t.Fatal(err)
	}
	leftValues := make([]complex128, ctx.params.Slots())
	rightValues := make([]complex128, ctx.params.Slots())
	leftValues[0], leftValues[1], leftValues[2] = 0.125+0.25i, -0.25+0.125i, 0.5-0.25i
	rightValues[0], rightValues[1], rightValues[2] = 0.25-0.125i, 0.375+0.25i, -0.125+0.5i
	basicError := primitivePrecisionBound(ctx, ctx.params.Scale(), 8)

	// Direct protected-upstream encryption, independent of encryptValues.
	directMessage := mkckks.NewMessage(ctx.params)
	copy(directMessage.Value, leftValues)
	directEncrypted := mkckks.NewEncryptor(ctx.params).EncryptMsgNew(directMessage, alice.pk)
	assertPrecisionBound(t, fullDecrypt(t, wrapDirect(ctx, []*mkckks.Ciphertext{directEncrypted}, 3, true), alice), leftValues[:3], basicError)

	left, err := encryptValues(ctx, alice.pk, [][]complex128{leftValues}, 3, true)
	if err != nil {
		t.Fatal(err)
	}
	right, err := encryptValues(ctx, bob.pk, [][]complex128{rightValues}, 3, true)
	if err != nil {
		t.Fatal(err)
	}
	expectedSum := make([]complex128, 3)
	for i := range expectedSum {
		expectedSum[i] = leftValues[i] + rightValues[i]
	}
	sumError := basicError + basicError + basicError

	wrappedSum, err := binaryCipher("add", left, right)
	if err != nil {
		t.Fatal(err)
	}
	directSumChunk := evaluator.AddNew(left.chunks[0], right.chunks[0])
	directSum := wrapDirect(ctx, []*mkckks.Ciphertext{directSumChunk}, 3, true)
	assertCipherMetadata(t, wrappedSum, directSum.chunks, true)
	assertPrecisionBound(t, fullDecrypt(t, wrappedSum, alice, bob), expectedSum, sumError)
	assertPrecisionBound(t, fullDecrypt(t, directSum, alice, bob), expectedSum, sumError)

	wrappedDifference, err := binaryCipher("sub", wrappedSum, right)
	if err != nil {
		t.Fatal(err)
	}
	directDifferenceChunk := evaluator.SubNew(wrappedSum.chunks[0], right.chunks[0])
	directDifference := wrapDirect(ctx, []*mkckks.Ciphertext{directDifferenceChunk}, 3, true)
	assertCipherMetadata(t, wrappedDifference, directDifference.chunks, true)
	differenceError := sumError + basicError + basicError
	assertPrecisionBound(t, fullDecrypt(t, wrappedDifference, alice, bob), leftValues[:3], differenceError)
	assertPrecisionBound(t, fullDecrypt(t, directDifference, alice, bob), leftValues[:3], differenceError)

	plainValues := make([]complex128, ctx.params.Slots())
	plainValues[0], plainValues[1], plainValues[2] = 0.5+0.25i, -0.25+0.5i, 0.75-0.125i
	plaintext := encodeValues(ctx, [][]complex128{plainValues}, 3, true)
	for _, subtract := range []bool{false, true} {
		wrapped, operationErr := addPlaintextCipher(wrappedSum, plaintext, subtract)
		if operationErr != nil {
			t.Fatal(operationErr)
		}
		directChunk := directAddPlaintext(ctx, wrappedSum.chunks[0], plainValues, subtract)
		expected := make([]complex128, 3)
		for i := range expected {
			if subtract {
				expected[i] = expectedSum[i] - plainValues[i]
			} else {
				expected[i] = expectedSum[i] + plainValues[i]
			}
		}
		plainAddError := sumError + basicError + primitivePrecisionBound(ctx, wrapped.chunks[0].Scale, 8)
		assertCipherMetadata(t, wrapped, []*mkckks.Ciphertext{directChunk}, true)
		assertPrecisionBound(t, fullDecrypt(t, wrapped, alice, bob), expected, plainAddError)
		assertPrecisionBound(t, fullDecrypt(t, wrapDirect(ctx, []*mkckks.Ciphertext{directChunk}, 3, true), alice, bob), expected, plainAddError)
	}

	scalarAddend := 0.125 - 0.0625i
	for _, subtract := range []bool{false, true} {
		wrapped, operationErr := addScalarCipher(wrappedSum, scalarAddend, subtract)
		if operationErr != nil {
			t.Fatal(operationErr)
		}
		directChunk := directAddPlaintext(ctx, wrappedSum.chunks[0], repeated(leftValues, scalarAddend), subtract)
		expected := make([]complex128, 3)
		for i := range expected {
			if subtract {
				expected[i] = expectedSum[i] - scalarAddend
			} else {
				expected[i] = expectedSum[i] + scalarAddend
			}
		}
		scalarAddError := sumError + basicError + primitivePrecisionBound(ctx, wrapped.chunks[0].Scale, 8)
		assertCipherMetadata(t, wrapped, []*mkckks.Ciphertext{directChunk}, true)
		assertPrecisionBound(t, fullDecrypt(t, wrapped, alice, bob), expected, scalarAddError)
		assertPrecisionBound(t, fullDecrypt(t, wrapDirect(ctx, []*mkckks.Ciphertext{directChunk}, 3, true), alice, bob), expected, scalarAddError)
	}

	wrappedInteger, err := scalarCipher(wrappedSum, 2)
	if err != nil {
		t.Fatal(err)
	}
	directInteger := wrappedSum.chunks[0].CopyNew()
	evaluator.MultByConst(wrappedSum.chunks[0], float64(2), directInteger)
	expectedInteger := make([]complex128, 3)
	for i := range expectedInteger {
		expectedInteger[i] = expectedSum[i] * 2
	}
	integerError := 2*sumError + primitivePrecisionBound(ctx, wrappedInteger.chunks[0].Scale, 8)
	assertCipherMetadata(t, wrappedInteger, []*mkckks.Ciphertext{directInteger}, true)
	assertPrecisionBound(t, fullDecrypt(t, wrappedInteger, alice, bob), expectedInteger, integerError)
	assertPrecisionBound(t, fullDecrypt(t, wrapDirect(ctx, []*mkckks.Ciphertext{directInteger}, 3, true), alice, bob), expectedInteger, integerError)

	fractional := 0.75 - 0.125i
	wrappedScalar, err := scalarCipher(wrappedSum, fractional)
	if err != nil {
		t.Fatal(err)
	}
	expectedScalar := make([]complex128, 3)
	for i := range expectedScalar {
		expectedScalar[i] = expectedSum[i] * fractional
	}
	directConstant := directEncode(ctx, repeated(leftValues, fractional), wrappedSum.chunks[0].Level(), ctx.params.Scale())
	directScalarChunk := evaluator.MulPtxtNew(wrappedSum.chunks[0], directConstant)
	scalarError := productPrecisionBound(ctx, wrappedScalar.chunks[0], expectedSum, repeated(expectedSum, fractional), sumError, basicError)
	assertCipherMetadata(t, wrappedScalar, []*mkckks.Ciphertext{directScalarChunk}, true)
	assertPrecisionBound(t, fullDecrypt(t, wrappedScalar, alice, bob), expectedScalar, scalarError)
	assertPrecisionBound(t, fullDecrypt(t, wrapDirect(ctx, []*mkckks.Ciphertext{directScalarChunk}, 3, true), alice, bob), expectedScalar, scalarError)

	wrappedPlain, err := plaintextCipher(wrappedSum, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	expectedPlain := make([]complex128, 3)
	for i := range expectedPlain {
		expectedPlain[i] = expectedSum[i] * plainValues[i]
	}
	directPlaintext := directEncode(ctx, plainValues, wrappedSum.chunks[0].Level(), ctx.params.Scale())
	directPlainChunk := evaluator.MulPtxtNew(wrappedSum.chunks[0], directPlaintext)
	plainProductError := productPrecisionBound(ctx, wrappedPlain.chunks[0], expectedSum, plainValues[:3], sumError, basicError)
	assertCipherMetadata(t, wrappedPlain, []*mkckks.Ciphertext{directPlainChunk}, true)
	assertPrecisionBound(t, fullDecrypt(t, wrappedPlain, alice, bob), expectedPlain, plainProductError)
	assertPrecisionBound(t, fullDecrypt(t, wrapDirect(ctx, []*mkckks.Ciphertext{directPlainChunk}, 3, true), alice, bob), expectedPlain, plainProductError)

	contributions := make([]*nativeEvalContribution, 0, 2)
	for _, party := range []*nativeParty{alice, bob} {
		contribution, contributionErr := generateEvalContribution(party, true, []int{1, 3}, true)
		if contributionErr != nil {
			t.Fatal(contributionErr)
		}
		contributions = append(contributions, contribution)
	}
	keys, err := combineEvalContributions(contributions)
	if err != nil {
		t.Fatal(err)
	}
	wrappedProduct, err := multiplyCipher(wrappedSum, wrappedSum, keys, false)
	if err != nil {
		t.Fatal(err)
	}
	expectedProduct := make([]complex128, 3)
	for i := range expectedProduct {
		expectedProduct[i] = expectedSum[i] * expectedSum[i]
	}
	// The direct path uses normal protected-upstream relinearization. The
	// bridge path independently uses operation-local hoisted decomposition.
	directProductChunk := evaluator.MulRelinNew(wrappedSum.chunks[0], wrappedSum.chunks[0], keys.rlin)
	directProduct := wrapDirect(ctx, []*mkckks.Ciphertext{directProductChunk}, 3, true)
	productError := productPrecisionBound(ctx, wrappedProduct.chunks[0], expectedSum, expectedSum, sumError, sumError)
	assertCipherMetadata(t, wrappedProduct, directProduct.chunks, true)
	assertPrecisionBound(t, fullDecrypt(t, wrappedProduct, alice, bob), expectedProduct, productError)
	assertPrecisionBound(t, fullDecrypt(t, directProduct, alice, bob), expectedProduct, productError)

	dropped, err := levelCipher(wrappedSum, "drop", 1)
	if err != nil {
		t.Fatal(err)
	}
	directDropped := evaluator.DropLevelNew(wrappedSum.chunks[0], 1)
	dropError := sumError + primitivePrecisionBound(ctx, dropped.chunks[0].Scale, 8)
	assertCipherMetadata(t, dropped, []*mkckks.Ciphertext{directDropped}, true)
	assertPrecisionBound(t, fullDecrypt(t, dropped, alice, bob), expectedSum, dropError)
	assertPrecisionBound(t, fullDecrypt(t, wrapDirect(ctx, []*mkckks.Ciphertext{directDropped}, 3, true), alice, bob), expectedSum, dropError)

	// Use the protected upstream in-place API as the independent reference.
	// Its allocating RescaleNew form returns an uninitialized result on a
	// no-op in this pinned revision; the bridge deliberately repairs that
	// allocation defect without changing protected code.
	rescaled, err := levelCipher(wrappedProduct, "rescale", ctx.params.Scale())
	if err != nil {
		t.Fatal(err)
	}
	directRescaled := wrappedProduct.chunks[0].CopyNew()
	if err = evaluator.Rescale(directRescaled, ctx.params.Scale(), directRescaled); err != nil {
		t.Fatal(err)
	}
	rescaleError := productError + primitivePrecisionBound(ctx, rescaled.chunks[0].Scale, 8)
	assertCipherMetadata(t, rescaled, []*mkckks.Ciphertext{directRescaled}, true)
	assertPrecisionBound(t, fullDecrypt(t, rescaled, alice, bob), expectedProduct, rescaleError)
	assertPrecisionBound(t, fullDecrypt(t, wrapDirect(ctx, []*mkckks.Ciphertext{directRescaled}, 3, true), alice, bob), expectedProduct, rescaleError)

	// Use every slot so a successful nonzero cyclic rotation cannot hide in
	// zero padding.
	rotationValues := make([]complex128, ctx.params.Slots())
	for index := range rotationValues {
		rotationValues[index] = complex(float64((index%31)-15)/64, float64((index%17)-8)/128)
	}
	rotationSource, err := encryptValues(ctx, alice.pk, [][]complex128{rotationValues}, len(rotationValues), true)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := rotateCipher(rotationSource, keys, 3, false)
	if err != nil {
		t.Fatal(err)
	}
	directRotated := evaluator.RotateNew(rotationSource.chunks[0], 3, keys.rot)
	expectedRotation := append(append([]complex128{}, rotationValues[3:]...), rotationValues[:3]...)
	rotationError := basicError + primitivePrecisionBound(ctx, rotated.chunks[0].Scale, 11)
	assertCipherMetadata(t, rotated, []*mkckks.Ciphertext{directRotated}, true)
	assertPrecisionBound(t, fullDecrypt(t, rotated, alice), expectedRotation, rotationError)
	assertPrecisionBound(t, fullDecrypt(t, wrapDirect(ctx, []*mkckks.Ciphertext{directRotated}, len(rotationValues), true), alice), expectedRotation, rotationError)

	identity, err := rotateCipher(wrappedSum, nil, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	assertPrecisionBound(t, fullDecrypt(t, identity, alice, bob), expectedSum, sumError)

	conjugated, err := conjugateCipher(wrappedSum, keys)
	if err != nil {
		t.Fatal(err)
	}
	expectedConjugate := make([]complex128, 3)
	for i := range expectedConjugate {
		expectedConjugate[i] = cmplx.Conj(expectedSum[i])
	}
	directConjugated := evaluator.ConjugateNew(wrappedSum.chunks[0], keys.conj)
	conjugateError := sumError + primitivePrecisionBound(ctx, conjugated.chunks[0].Scale, 11)
	assertCipherMetadata(t, conjugated, []*mkckks.Ciphertext{directConjugated}, true)
	assertPrecisionBound(t, fullDecrypt(t, conjugated, alice, bob), expectedConjugate, conjugateError)
	assertPrecisionBound(t, fullDecrypt(t, wrapDirect(ctx, []*mkckks.Ciphertext{directConjugated}, 3, true), alice, bob), expectedConjugate, conjugateError)

	shares := make([]*nativeShare, 0, 2)
	for _, party := range []*nativeParty{alice, bob} {
		share, shareErr := partialDecrypt(party, wrappedProduct)
		if shareErr != nil {
			t.Fatal(shareErr)
		}
		shares = append(shares, share)
	}
	collective, err := collectiveDecrypt(wrappedProduct, shares)
	if err != nil {
		t.Fatal(err)
	}
	full := fullDecrypt(t, wrappedProduct, alice, bob)
	for i := range full {
		if collective[i] != full[i] {
			t.Fatalf("collective and full decryption differ at %d: %v != %v", i, collective[i], full[i])
		}
	}

	// Generated mixed-depth sequence through predictable level exhaustion.
	bridgeCircuit := wrappedSum
	circuitExpected := append([]complex128(nil), expectedSum...)
	circuitError := sumError
	for bridgeCircuit.chunks[0].Level() > 0 {
		directCircuit := mkckks.NewEvaluator(ctx.params).MulRelinNew(
			bridgeCircuit.chunks[0], bridgeCircuit.chunks[0], keys.rlin,
		)
		bridgeCircuit, err = multiplyCipher(bridgeCircuit, bridgeCircuit, keys, false)
		if err != nil {
			t.Fatal(err)
		}
		previousMaximum := maximumMagnitude(circuitExpected)
		for index := range circuitExpected {
			circuitExpected[index] *= circuitExpected[index]
		}
		circuitError = 2*previousMaximum*circuitError +
			circuitError*circuitError +
			primitivePrecisionBound(ctx, bridgeCircuit.chunks[0].Scale, 12)
		assertCipherMetadata(t, bridgeCircuit, []*mkckks.Ciphertext{directCircuit}, true)
		assertPrecisionBound(t, fullDecrypt(t, bridgeCircuit, alice, bob), circuitExpected, circuitError)
		assertPrecisionBound(t, fullDecrypt(t, wrapDirect(ctx, []*mkckks.Ciphertext{directCircuit}, 3, true), alice, bob), circuitExpected, circuitError)
	}
	if _, err = multiplyCipher(bridgeCircuit, bridgeCircuit, keys, false); err == nil {
		t.Fatal("multiplication at level zero unexpectedly succeeded")
	}
}

func TestDifferentialOperationsPN14(t *testing.T) { testDifferentialOperations(t, "PN14QP439") }

func TestDifferentialOperationsPN15(t *testing.T) { testDifferentialOperations(t, "PN15QP880") }

func TestCollectiveDecryptionPartyCountMatrix(t *testing.T) {
	for _, preset := range []string{"PN14QP439", "PN15QP880"} {
		t.Run(preset, func(t *testing.T) {
			ctx := differentialContext(t, preset)
			parties := make([]*nativeParty, 8)
			ciphertexts := make([]*nativeCiphertext, 8)
			for index := range parties {
				party, err := generateParty(ctx, fmt.Sprintf("matrix-party-%d", index))
				if err != nil {
					t.Fatal(err)
				}
				parties[index] = party
				values := make([]complex128, ctx.params.Slots())
				values[0] = complex(float64(index+1)/16, -float64(index+1)/32)
				ciphertexts[index], err = encryptValues(ctx, party.pk, [][]complex128{values}, 1, true)
				if err != nil {
					t.Fatal(err)
				}
			}

			combined := ciphertexts[0]
			expected := []complex128{complex(1.0/16.0, -1.0/32.0)}
			checkpoints := map[int]bool{1: true, 2: true, 4: true, 8: true}
			for count := 1; count <= len(parties); count++ {
				if count > 1 {
					var err error
					combined, err = binaryCipher("add", combined, ciphertexts[count-1])
					if err != nil {
						t.Fatal(err)
					}
					expected[0] += complex(float64(count)/16, -float64(count)/32)
				}
				if !checkpoints[count] {
					continue
				}
				shares := make([]*nativeShare, count)
				for index, party := range parties[:count] {
					var err error
					shares[index], err = partialDecrypt(party, combined)
					if err != nil {
						t.Fatal(err)
					}
				}
				collective, err := collectiveDecrypt(combined, shares)
				if err != nil {
					t.Fatal(err)
				}
				full := fullDecrypt(t, combined, parties[:count]...)
				if collective[0] != full[0] {
					t.Fatalf("%d-party collective decryption differs from full decryption", count)
				}
				assertPrecision(t, ctx, collective, expected, 8)
			}
		})
	}
}

func generatedCircuitCount(preset string) int {
	name := "MKCKKS_CIRCUIT_COUNT_PN14"
	if preset == "PN15QP880" {
		name = "MKCKKS_CIRCUIT_COUNT_PN15"
	}
	if value := os.Getenv(name); value != "" {
		count, err := strconv.Atoi(value)
		if err == nil && count > 0 && count <= 10000 {
			return count
		}
	}
	return 20
}

func testGeneratedDifferentialCircuits(t *testing.T, preset string) {
	t.Helper()
	ctx := differentialContext(t, preset)
	alice, err := generateParty(ctx, "generated-alice")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := generateParty(ctx, "generated-bob")
	if err != nil {
		t.Fatal(err)
	}
	contributions := make([]*nativeEvalContribution, 2)
	for index, party := range []*nativeParty{alice, bob} {
		contributions[index], err = generateEvalContribution(party, true, []int{-1, 1, 3}, true)
		if err != nil {
			t.Fatal(err)
		}
	}
	keys, err := combineEvalContributions(contributions)
	if err != nil {
		t.Fatal(err)
	}
	emptyContribution, err := generateEvalContribution(alice, false, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	emptyKeys, err := combineEvalContributions([]*nativeEvalContribution{emptyContribution})
	if err != nil {
		t.Fatal(err)
	}
	plainValues := make([]complex128, ctx.params.Slots())
	for index, value := range []complex128{0.5 + 0.125i, -0.25, 0.75 - 0.125i, 0.125i, -0.5, 0.25, 0.5i, -0.125} {
		plainValues[index] = value
	}
	plain := encodeValues(ctx, [][]complex128{plainValues}, 8, true)

	for circuitIndex := 0; circuitIndex < generatedCircuitCount(preset); circuitIndex++ {
		seed := int64(0x4d4b0000 + circuitIndex)
		rng := rand.New(rand.NewSource(seed)) // #nosec G404 -- deterministic test generation.
		expected := make([]complex128, ctx.params.Slots())
		for index := 0; index < 8; index++ {
			expected[index] = complex(rng.Float64()*0.5-0.25, rng.Float64()*0.5-0.25)
		}
		current, operationErr := encryptValues(ctx, alice.pk, [][]complex128{append([]complex128(nil), expected...)}, 8, true)
		if operationErr != nil {
			t.Fatal(operationErr)
		}
		if circuitIndex%5 == 0 {
			before, serializeErr := writeCipherPayload(current)
			if serializeErr != nil {
				t.Fatal(serializeErr)
			}
			if failed, invalidErr := multiplyCipher(current, current, emptyKeys, false); invalidErr == nil || failed != nil {
				t.Fatalf("preset=%s seed=%d: missing relinearization key was not rejected atomically", preset, seed)
			}
			after, serializeErr := writeCipherPayload(current)
			if serializeErr != nil {
				t.Fatal(serializeErr)
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("preset=%s seed=%d: failed transition mutated its input", preset, seed)
			}
		}
		trace := make([]string, 0, 10)
		steps := 3 + rng.Intn(8)
		for step := 0; step < steps; step++ {
			operations := []string{"add-scalar", "integer", "rotate", "serialize", "add-plaintext"}
			if current.chunks[0].Level() > 0 {
				operations = append(operations, "fractional", "plaintext", "square", "drop", "rescale")
			}
			if current.chunks[0].Level() == ctx.params.MaxLevel() {
				operations = append(operations, "conjugate", "aggregate")
			}
			operation := operations[rng.Intn(len(operations))]
			trace = append(trace, operation)
			evaluator := mkckks.NewEvaluator(ctx.params)
			var next *nativeCiphertext
			var direct *mkckks.Ciphertext
			switch operation {
			case "add-scalar":
				scalar := 0.0625 - 0.03125i
				next, operationErr = addScalarCipher(current, scalar, false)
				direct = directAddPlaintext(ctx, current.chunks[0], repeated(expected, scalar), false)
				for index := 0; index < 8; index++ {
					expected[index] += scalar
				}
			case "integer":
				choices := []float64{-1, 0, 1, 2}
				scalar := choices[rng.Intn(len(choices))]
				next, operationErr = scalarCipher(current, complex(scalar, 0))
				direct = current.chunks[0].CopyNew()
				evaluator.MultByConst(direct, scalar, direct)
				for index := range expected {
					expected[index] *= complex(scalar, 0)
				}
			case "fractional":
				scalar := 0.5 - 0.125i
				next, operationErr = scalarCipher(current, scalar)
				constant := directEncode(ctx, repeated(expected, scalar), current.chunks[0].Level(), ctx.params.Scale())
				direct = evaluator.MulPtxtNew(current.chunks[0], constant)
				for index := range expected {
					expected[index] *= scalar
				}
			case "plaintext":
				next, operationErr = plaintextCipher(current, plain)
				encoded := directEncode(ctx, plainValues, current.chunks[0].Level(), ctx.params.Scale())
				direct = evaluator.MulPtxtNew(current.chunks[0], encoded)
				for index := range expected {
					expected[index] *= plainValues[index]
				}
			case "square":
				direct = evaluator.MulRelinNew(current.chunks[0], current.chunks[0], keys.rlin)
				next, operationErr = multiplyCipher(current, current, keys, false)
				for index := range expected {
					expected[index] *= expected[index]
				}
			case "rotate":
				rotations := []int{-1, 1, 3}
				rotation := rotations[rng.Intn(len(rotations))]
				direct = evaluator.RotateNew(current.chunks[0], rotation, keys.rot)
				next, operationErr = rotateCipher(current, keys, rotation, false)
				normalized := rotation % len(expected)
				if normalized < 0 {
					normalized += len(expected)
				}
				expected = append(append([]complex128(nil), expected[normalized:]...), expected[:normalized]...)
			case "conjugate":
				direct = evaluator.ConjugateNew(current.chunks[0], keys.conj)
				next, operationErr = conjugateCipher(current, keys)
				for index := range expected {
					expected[index] = cmplx.Conj(expected[index])
				}
			case "drop":
				direct = evaluator.DropLevelNew(current.chunks[0], 1)
				next, operationErr = levelCipher(current, "drop", 1)
			case "rescale":
				direct = current.chunks[0].CopyNew()
				operationErr = evaluator.Rescale(direct, ctx.params.Scale(), direct)
				if operationErr == nil {
					next, operationErr = levelCipher(current, "rescale", ctx.params.Scale())
				}
			case "aggregate":
				zeroValues := make([]complex128, ctx.params.Slots())
				addition, encryptErr := encryptValues(ctx, bob.pk, [][]complex128{zeroValues}, 8, true)
				if encryptErr != nil {
					t.Fatal(encryptErr)
				}
				direct = evaluator.AddNew(current.chunks[0], addition.chunks[0])
				next, operationErr = binaryCipher("add", current, addition)
			case "serialize":
				artifact, serializeErr := serializeEntry(registryEntry{kind: kindCiphertext, value: current})
				if serializeErr != nil {
					t.Fatal(serializeErr)
				}
				entry, deserializeErr := deserializeEntry(ctx, artifact)
				if deserializeErr != nil {
					t.Fatal(deserializeErr)
				}
				next = entry.value.(*nativeCiphertext)
				direct = current.chunks[0].CopyNew()
			case "add-plaintext":
				next, operationErr = addPlaintextCipher(current, plain, false)
				direct = directAddPlaintext(ctx, current.chunks[0], plainValues, false)
				for index := range expected {
					expected[index] += plainValues[index]
				}
			}
			if operationErr != nil {
				t.Fatalf("preset=%s seed=%d trace=%v: %v", preset, seed, trace, operationErr)
			}
			assertCipherMetadata(t, next, []*mkckks.Ciphertext{direct}, true)
			if next.tracking.magnitudeBound+math.SmallestNonzeroFloat64 < maximumMagnitude(expected) {
				t.Fatalf("preset=%s seed=%d trace=%v: magnitude tracking underflow", preset, seed, trace)
			}
			bound := next.tracking.errorBound
			if next.tracking.rangeExceeded || bound < 0 || math.IsNaN(bound) || math.IsInf(bound, 0) {
				t.Fatalf("normalized circuit unexpectedly left tested range: preset=%s seed=%d trace=%v tracking=%+v", preset, seed, trace, next.tracking)
			}
			assertPrecisionBound(t, fullDecrypt(t, next, alice, bob), expected[:8], bound)
			assertPrecisionBound(
				t,
				fullDecrypt(t, wrapDirect(ctx, []*mkckks.Ciphertext{direct}, 8, true), alice, bob),
				expected[:8],
				bound,
			)
			current = next
		}
	}
}

func TestGeneratedDifferentialCircuitsPN14(t *testing.T) {
	testGeneratedDifferentialCircuits(t, "PN14QP439")
}

func TestGeneratedDifferentialCircuitsPN15(t *testing.T) {
	testGeneratedDifferentialCircuits(t, "PN15QP880")
}

func testMultiChunkDifferentialChain(t *testing.T, preset string) {
	t.Helper()
	ctx := differentialContext(t, preset)
	alice, err := generateParty(ctx, "chunks-alice")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := generateParty(ctx, "chunks-bob")
	if err != nil {
		t.Fatal(err)
	}
	contributions := make([]*nativeEvalContribution, 2)
	for index, party := range []*nativeParty{alice, bob} {
		contributions[index], err = generateEvalContribution(party, true, []int{1}, false)
		if err != nil {
			t.Fatal(err)
		}
	}
	keys, err := combineEvalContributions(contributions)
	if err != nil {
		t.Fatal(err)
	}
	slots := ctx.params.Slots()
	length := slots + 3
	values := [][]complex128{make([]complex128, slots), make([]complex128, slots)}
	zeros := [][]complex128{make([]complex128, slots), make([]complex128, slots)}
	for index := 0; index < slots; index++ {
		values[0][index] = complex(float64(index%17-8)/32, float64(index%11-5)/64)
	}
	values[1][0], values[1][1], values[1][2] = 0.25+0.125i, -0.5+0.25i, 0.75-0.125i
	current, err := encryptValues(ctx, alice.pk, values, length, true)
	if err != nil {
		t.Fatal(err)
	}
	addition, err := encryptValues(ctx, bob.pk, zeros, length, true)
	if err != nil {
		t.Fatal(err)
	}
	expected := [][]complex128{append([]complex128(nil), values[0]...), append([]complex128(nil), values[1]...)}

	flatten := func(chunks [][]complex128) []complex128 {
		result := append(append([]complex128(nil), chunks[0]...), chunks[1][:3]...)
		return result
	}
	check := func(next *nativeCiphertext, direct []*mkckks.Ciphertext) {
		assertCipherMetadata(t, next, direct, true)
		if next.tracking.rangeExceeded {
			t.Fatalf("multi-chunk chain unexpectedly left tracked range: %+v", next.tracking)
		}
		want := flatten(expected)
		assertPrecisionBound(t, fullDecrypt(t, next, alice, bob), want, next.tracking.errorBound)
		assertPrecisionBound(
			t,
			fullDecrypt(t, wrapDirect(ctx, direct, length, true), alice, bob),
			want,
			next.tracking.errorBound,
		)
	}

	evaluator := mkckks.NewEvaluator(ctx.params)
	direct := make([]*mkckks.Ciphertext, len(current.chunks))
	for index := range direct {
		direct[index] = evaluator.AddNew(current.chunks[index], addition.chunks[index])
	}
	current, err = binaryCipher("add", current, addition)
	if err != nil {
		t.Fatal(err)
	}
	check(current, direct)

	scalar := 0.0625 - 0.03125i
	direct = make([]*mkckks.Ciphertext, len(current.chunks))
	for index := range direct {
		plainScalar := make([]complex128, slots)
		used := slots
		if index == 1 {
			used = 3
		}
		for slot := 0; slot < used; slot++ {
			plainScalar[slot] = scalar
			expected[index][slot] += scalar
		}
		direct[index] = directAddPlaintext(ctx, current.chunks[index], plainScalar, false)
	}
	current, err = addScalarCipher(current, scalar, false)
	if err != nil {
		t.Fatal(err)
	}
	check(current, direct)

	direct = make([]*mkckks.Ciphertext, len(current.chunks))
	for index := range direct {
		direct[index] = evaluator.RotateNew(current.chunks[index], 1, keys.rot)
		expected[index] = append(append([]complex128(nil), expected[index][1:]...), expected[index][0])
	}
	current, err = rotateCipher(current, keys, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	check(current, direct)

	factors := [][]complex128{make([]complex128, slots), make([]complex128, slots)}
	for index := range factors[0] {
		factors[0][index] = 0.5 - 0.125i
	}
	for index := 0; index < 3; index++ {
		factors[1][index] = 0.5 - 0.125i
	}
	plain := encodeValues(ctx, factors, length, true)
	direct = make([]*mkckks.Ciphertext, len(current.chunks))
	for index := range direct {
		direct[index] = evaluator.MulPtxtNew(
			current.chunks[index],
			directEncode(ctx, factors[index], current.chunks[index].Level(), ctx.params.Scale()),
		)
		for slot := range expected[index] {
			expected[index][slot] *= factors[index][slot]
		}
	}
	current, err = plaintextCipher(current, plain)
	if err != nil {
		t.Fatal(err)
	}
	check(current, direct)

	direct = make([]*mkckks.Ciphertext, len(current.chunks))
	for index := range direct {
		direct[index] = evaluator.MulRelinNew(current.chunks[index], current.chunks[index], keys.rlin)
		for slot := range expected[index] {
			expected[index][slot] *= expected[index][slot]
		}
	}
	current, err = multiplyCipher(current, current, keys, false)
	if err != nil {
		t.Fatal(err)
	}
	check(current, direct)
}

func TestMultiChunkDifferentialChain(t *testing.T) {
	for _, preset := range []string{"PN14QP439", "PN15QP880"} {
		t.Run(preset, func(t *testing.T) { testMultiChunkDifferentialChain(t, preset) })
	}
}
