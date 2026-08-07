// SPDX-License-Identifier: MIT
package main

import (
	"fmt"
	"sync"
	"testing"
)

func TestWorkerAndConcurrentOperationMatrix(t *testing.T) {
	for _, workers := range []int{1, 2, 4, 8} {
		t.Run(fmt.Sprintf("workers-%d", workers), func(t *testing.T) {
			ctx := testContext(t)
			ctx.workers = workers
			party, err := generateParty(ctx, fmt.Sprintf("worker-party-%d", workers))
			if err != nil {
				t.Fatal(err)
			}
			values := [][]complex128{
				make([]complex128, ctx.params.Slots()),
				make([]complex128, ctx.params.Slots()),
			}
			values[0][0], values[1][0] = 0.125+0.25i, -0.25+0.125i
			ciphertext, err := encryptValues(ctx, party.pk, values, ctx.params.Slots()+1, true)
			if err != nil {
				t.Fatal(err)
			}
			contribution, err := generateEvalContribution(party, true, []int{1}, true)
			if err != nil {
				t.Fatal(err)
			}
			keys, err := combineEvalContributions([]*nativeEvalContribution{contribution})
			if err != nil {
				t.Fatal(err)
			}
			intermediate, err := addScalarCipher(ciphertext, 0.0625-0.03125i, false)
			if err != nil {
				t.Fatal(err)
			}
			before, err := writeCipherPayload(intermediate)
			if err != nil {
				t.Fatal(err)
			}

			var wait sync.WaitGroup
			errors := make(chan error, 24)
			for goroutine := 0; goroutine < 4; goroutine++ {
				wait.Add(1)
				go func() {
					defer wait.Done()
					if _, operationErr := binaryCipher("add", intermediate, ciphertext); operationErr != nil {
						errors <- operationErr
					}
					if _, operationErr := multiplyCipher(intermediate, intermediate, keys, false); operationErr != nil {
						errors <- operationErr
					}
					if _, operationErr := rotateCipher(intermediate, keys, 1, false); operationErr != nil {
						errors <- operationErr
					}
					if _, operationErr := conjugateCipher(intermediate, keys); operationErr != nil {
						errors <- operationErr
					}
					if _, operationErr := serializeEntry(registryEntry{kind: kindCiphertext, value: intermediate}); operationErr != nil {
						errors <- operationErr
					}
					if _, operationErr := partialDecrypt(party, intermediate); operationErr != nil {
						errors <- operationErr
					}
				}()
			}
			wait.Wait()
			close(errors)
			for operationErr := range errors {
				t.Error(operationErr)
			}
			after, err := writeCipherPayload(intermediate)
			if err != nil {
				t.Fatal(err)
			}
			if string(before) != string(after) {
				t.Fatal("concurrent read-only operations mutated shared ciphertext metadata or payload")
			}
		})
	}
}
