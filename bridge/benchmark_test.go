// SPDX-License-Identifier: MIT
package main

import (
	"testing"

	"mk-lattigo/mkckks"
)

func BenchmarkDirectGoAdd(b *testing.B) {
	b.ReportAllocs()
	ctx := testContext(b)
	alice, err := generateParty(ctx, "benchmark-direct-go")
	if err != nil {
		b.Fatal(err)
	}
	values := [][]complex128{make([]complex128, ctx.params.Slots())}
	for i := 0; i < 1024; i++ {
		values[0][i] = complex(float64(i)/1024, -float64(i)/2048)
	}
	left, err := encryptValues(ctx, alice.pk, values, 1024, true)
	if err != nil {
		b.Fatal(err)
	}
	right, err := encryptValues(ctx, alice.pk, values, 1024, true)
	if err != nil {
		b.Fatal(err)
	}
	directEvaluator := mkckks.NewEvaluator(ctx.params)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = directEvaluator.AddNew(left.chunks[0], right.chunks[0])
	}
}

func BenchmarkBridgeModelAdd(b *testing.B) {
	b.ReportAllocs()
	ctx := testContext(b)
	alice, err := generateParty(ctx, "benchmark-bridge-model")
	if err != nil {
		b.Fatal(err)
	}
	values := [][]complex128{make([]complex128, ctx.params.Slots())}
	left, err := encryptValues(ctx, alice.pk, values, 1024, true)
	if err != nil {
		b.Fatal(err)
	}
	right, err := encryptValues(ctx, alice.pk, values, 1024, true)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err = binaryCipher("add", left, right); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkEvaluationInputs(b *testing.B, partyID string) (
	*nativeContext,
	*nativeCiphertext,
	*nativeCiphertext,
	*nativeEvalSet,
) {
	b.Helper()
	ctx := testContext(b)
	party, err := generateParty(ctx, partyID)
	if err != nil {
		b.Fatal(err)
	}
	values := [][]complex128{make([]complex128, ctx.params.Slots())}
	for index := 0; index < 1024; index++ {
		values[0][index] = complex(float64(index)/2048, -float64(index)/4096)
	}
	left, err := encryptValues(ctx, party.pk, values, 1024, true)
	if err != nil {
		b.Fatal(err)
	}
	right, err := encryptValues(ctx, party.pk, values, 1024, true)
	if err != nil {
		b.Fatal(err)
	}
	contribution, err := generateEvalContribution(party, true, []int{1}, false)
	if err != nil {
		b.Fatal(err)
	}
	keys, err := combineEvalContributions([]*nativeEvalContribution{contribution})
	if err != nil {
		b.Fatal(err)
	}
	return ctx, left, right, keys
}

func BenchmarkDirectGoMultiply(b *testing.B) {
	b.ReportAllocs()
	ctx, left, right, keys := benchmarkEvaluationInputs(b, "benchmark-direct-multiply")
	evaluator := mkckks.NewEvaluator(ctx.params)
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		_ = evaluator.MulRelinNew(left.chunks[0], right.chunks[0], keys.rlin)
	}
}

func BenchmarkBridgeModelMultiply(b *testing.B) {
	b.ReportAllocs()
	_, left, right, keys := benchmarkEvaluationInputs(b, "benchmark-bridge-multiply")
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, err := multiplyCipher(left, right, keys, false); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDirectGoRotate(b *testing.B) {
	b.ReportAllocs()
	ctx, left, _, keys := benchmarkEvaluationInputs(b, "benchmark-direct-rotate")
	evaluator := mkckks.NewEvaluator(ctx.params)
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		_ = evaluator.RotateNew(left.chunks[0], 1, keys.rot)
	}
}

func BenchmarkBridgeModelRotate(b *testing.B) {
	b.ReportAllocs()
	_, left, _, keys := benchmarkEvaluationInputs(b, "benchmark-bridge-rotate")
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, err := rotateCipher(left, keys, 1, false); err != nil {
			b.Fatal(err)
		}
	}
}
