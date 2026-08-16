// SPDX-License-Identifier: MIT
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"math/cmplx"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ldsec/lattigo/v2/ring"
	"mk-lattigo/mkckks"
)

func testContext(t testing.TB) *nativeContext {
	t.Helper()
	dto := parameterLiteralDTO{
		LogN: 14, LogSlots: 13,
		Q:     []uint64{0x7ffffffffe70001, 0xffffffff00001, 0xfffffffe40001, 0xfffffffe20001, 0xfffffffbe0001, 0xfffffffa60001},
		P:     []uint64{0xffffffffffc0001, 0xfffffffff840001},
		Scale: 1 << 52, Sigma: 3.2,
	}
	raw, _ := json.Marshal(dto)
	ctx, err := newContext(raw, 1)
	if err != nil {
		t.Fatal(err)
	}
	return ctx
}

func TestDistributedDecryptionMatchesMessage(t *testing.T) {
	ctx := testContext(t)
	alice, _ := generateParty(ctx, "alice")
	bob, _ := generateParty(ctx, "bob")
	a := [][]complex128{make([]complex128, ctx.params.Slots())}
	b := [][]complex128{make([]complex128, ctx.params.Slots())}
	a[0][0], a[0][1] = 1.25+0.5i, -2.0+0.25i
	b[0][0], b[0][1] = 2.5-0.75i, 1.0+0.5i
	ca, err := encryptValues(ctx, alice.pk, a, 2, true)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := encryptValues(ctx, bob.pk, b, 2, true)
	if err != nil {
		t.Fatal(err)
	}
	sum, err := binaryCipher("add", ca, cb)
	if err != nil {
		t.Fatal(err)
	}
	sa, err := partialDecrypt(alice, sum)
	if err != nil {
		t.Fatal(err)
	}
	sb, err := partialDecrypt(bob, sum)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := collectiveDecrypt(sum, []*nativeShare{sa, sb})
	if err != nil {
		t.Fatal(err)
	}
	for i, expected := range []complex128{3.75 - 0.25i, -1 + 0.75i} {
		if cmplx.Abs(decoded[i]-expected) > 1e-8 {
			t.Fatalf("slot %d: got %v want %v", i, decoded[i], expected)
		}
	}
}

func TestContextArtifactRoundTrip(t *testing.T) {
	ctx := testContext(t)
	payload, err := writeContextPayload(ctx)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := wrapArtifact(kindContext, ctx.fingerprint, payload)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := deserializeEntry(nil, artifact)
	if err != nil {
		t.Fatal(err)
	}
	restored := entry.value.(*nativeContext)
	if restored.fingerprint != ctx.fingerprint {
		t.Fatal("context fingerprint changed after round trip")
	}
	artifact[len(artifact)-1] ^= 1
	if _, err := deserializeEntry(nil, artifact); err == nil {
		t.Fatal("corrupted artifact was accepted")
	}
}

func TestRegistryRejectsStaleHandles(t *testing.T) {
	handle := putObject(kindContext, testContext(t))
	if err := releaseObject(handle); err != nil {
		t.Fatal(err)
	}
	if _, err := getObject(handle, kindContext); err == nil {
		t.Fatal("stale handle accepted")
	}
	if err := releaseObject(handle); err == nil {
		t.Fatal("stale handle released twice")
	}
}

func TestModelEvaluatorAndEveryArtifactRoundTrip(t *testing.T) {
	ctx := testContext(t)
	ctx.workers = 2
	alice, err := generateParty(ctx, "model-alice")
	if err != nil {
		t.Fatal(err)
	}
	values := [][]complex128{make([]complex128, ctx.params.Slots())}
	values[0][0], values[0][1] = 0.25+0.5i, -0.75+0.125i
	ciphertext, err := encryptValues(ctx, alice.pk, values, 2, true)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := encodeValues(ctx, values, 2, true)

	added, err := addScalarCipher(ciphertext, 1.5-0.25i, false)
	if err != nil {
		t.Fatal(err)
	}
	subtracted, err := addPlaintextCipher(added, plaintext, true)
	if err != nil {
		t.Fatal(err)
	}
	scaled, err := scalarCipher(subtracted, 2.0)
	if err != nil {
		t.Fatal(err)
	}
	plaintextProduct, err := plaintextCipher(scaled, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if plaintextProduct.length != 2 {
		t.Fatal("plaintext product lost logical length")
	}

	contribution, err := generateEvalContribution(alice, true, []int{1}, true)
	if err != nil {
		t.Fatal(err)
	}
	keyset, err := combineEvalContributions([]*nativeEvalContribution{contribution})
	if err != nil {
		t.Fatal(err)
	}
	product, err := multiplyCipher(ciphertext, ciphertext, keyset, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = multiplyCipher(ciphertext, ciphertext, keyset, true); err != nil {
		t.Fatal(err)
	}
	if _, err = levelCipher(product, "drop", 1); err != nil {
		t.Fatal(err)
	}
	if _, err = levelCipher(product, "rescale", ctx.params.Scale()); err != nil {
		t.Fatal(err)
	}
	if _, err = rotateCipher(ciphertext, keyset, 1, false); err != nil {
		t.Fatal(err)
	}
	if _, err = rotateCipher(ciphertext, keyset, 1, true); err != nil {
		t.Fatal(err)
	}
	if _, err = conjugateCipher(ciphertext, keyset); err != nil {
		t.Fatal(err)
	}
	if got := participantIDs(ciphertext); !reflect.DeepEqual(got, []string{"model-alice"}) {
		t.Fatalf("unexpected participant IDs: %v", got)
	}

	share, err := partialDecrypt(alice, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	contextArtifact, err := serializeEntry(registryEntry{kind: kindContext, value: ctx})
	if err != nil {
		t.Fatal(err)
	}
	contextEntry, err := deserializeEntry(nil, contextArtifact)
	if err != nil {
		t.Fatal(err)
	}
	restoredContext := contextEntry.value.(*nativeContext)

	entries := []registryEntry{
		{kind: kindParty, value: alice},
		{kind: kindPublicKey, value: &nativePublicKey{ctx: ctx, pk: clonePublicKey(alice.pk)}},
		{kind: kindPlaintext, value: plaintext},
		{kind: kindCiphertext, value: ciphertext},
		{kind: kindShare, value: share},
		{kind: kindEvalContribution, value: contribution},
		{kind: kindEvalSet, value: keyset},
	}
	for _, original := range entries {
		artifact, serializeErr := serializeEntry(original)
		if serializeErr != nil {
			t.Fatalf("serialize kind %d: %v", original.kind, serializeErr)
		}
		restored, deserializeErr := deserializeEntry(restoredContext, artifact)
		if deserializeErr != nil {
			t.Fatalf("deserialize kind %d: %v", original.kind, deserializeErr)
		}
		if restored.kind != original.kind {
			t.Fatalf("artifact kind changed: got %d want %d", restored.kind, original.kind)
		}
	}
}

func TestModelValidationFailures(t *testing.T) {
	ctx := testContext(t)
	if _, err := generateParty(ctx, ""); err == nil {
		t.Fatal("empty party ID accepted")
	}
	if _, err := generateParty(ctx, "0"); err == nil {
		t.Fatal("reserved party ID accepted")
	}
	alice, err := generateParty(ctx, "validation-alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = generateParty(ctx, "validation-alice"); err == nil {
		t.Fatal("duplicate party ID accepted")
	}
	if _, err = combineEvalContributions(nil); err == nil {
		t.Fatal("empty evaluation contribution set accepted")
	}
	values := [][]complex128{make([]complex128, ctx.params.Slots())}
	ciphertext, err := encryptValues(ctx, alice.pk, values, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = levelCipher(ciphertext, "drop", 99); err == nil {
		t.Fatal("invalid level drop accepted")
	}
	if _, err = levelCipher(ciphertext, "unknown", 1); err == nil {
		t.Fatal("unknown level operation accepted")
	}
	if _, err = deserializeEntry(nil, []byte("invalid")); err == nil {
		t.Fatal("malformed artifact accepted")
	}
	if _, err = deserializeEntry(nil, mustArtifact(t, registryEntry{
		kind: kindPublicKey, value: &nativePublicKey{ctx: ctx, pk: alice.pk},
	})); err == nil {
		t.Fatal("non-context artifact imported without a context")
	}
}

func TestArtifactSemanticValidation(t *testing.T) {
	ctx := testContext(t)
	alice, err := generateParty(ctx, "artifact-validation-alice")
	if err != nil {
		t.Fatal(err)
	}
	values := [][]complex128{make([]complex128, ctx.params.Slots())}
	values[0][0] = 1 + 0.25i
	ciphertext, err := encryptValues(ctx, alice.pk, values, 1, true)
	if err != nil {
		t.Fatal(err)
	}
	share, err := partialDecrypt(alice, ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if !equalStrings([]string{"0", "alice"}, []string{"0", "alice"}) ||
		equalStrings([]string{"0"}, []string{"0", "alice"}) ||
		equalStrings([]string{"0", "alice"}, []string{"0", "bob"}) {
		t.Fatal("string-slice comparison is inconsistent")
	}

	q := ctx.params.Q()
	if err = validatePolyModuli(nil, q, true); err == nil {
		t.Fatal("nil polynomial accepted")
	}
	if err = validatePolyModuli(ring.NewPoly(ctx.params.N(), len(q)+1), q, true); err == nil {
		t.Fatal("polynomial with excess moduli accepted")
	}
	prefix := alice.sk.Value.Q.CopyNew()
	prefix.Coeffs = prefix.Coeffs[:len(prefix.Coeffs)-1]
	if err = validatePolyModuli(prefix, q, false); err == nil {
		t.Fatal("truncated exact-level polynomial accepted")
	}
	emptyCoefficients := alice.sk.Value.Q.CopyNew()
	emptyCoefficients.Coeffs[0] = nil
	if err = validatePolyModuli(emptyCoefficients, q, true); err == nil {
		t.Fatal("empty polynomial coefficient vector accepted")
	}
	unreduced := alice.sk.Value.Q.CopyNew()
	unreduced.Coeffs[0][0] = q[0]
	if err = validatePolyModuli(unreduced, q, true); err == nil {
		t.Fatal("unreduced polynomial coefficient accepted")
	}
	wrongDegree := alice.sk.Value.Q.CopyNew()
	wrongDegree.Coeffs[0] = wrongDegree.Coeffs[0][:1]
	if err = validatePolyQ(ctx, wrongDegree, true); err == nil {
		t.Fatal("wrong polynomial degree accepted")
	}
	wrongP := alice.sk.Value.CopyNew()
	wrongP.P.Coeffs[0] = wrongP.P.Coeffs[0][:1]
	if err = validatePolyQP(ctx, wrongP); err == nil {
		t.Fatal("wrong P polynomial degree accepted")
	}
	if err = validateSwitchingKey(ctx, nil); err == nil {
		t.Fatal("nil switching key accepted")
	}
	if err = validateRelinearizationKey(ctx, nil); err != nil {
		t.Fatalf("absent optional relinearization key rejected: %v", err)
	}
	if err = validateRotationKey(ctx, nil); err == nil {
		t.Fatal("nil rotation key accepted")
	}
	if err = validateConjugationKey(ctx, nil); err != nil {
		t.Fatalf("absent optional conjugation key rejected: %v", err)
	}

	invalidCiphertext := *ciphertext
	invalidCiphertext.length = 0
	payload, err := writeCipherPayload(&invalidCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = readCipherPayload(ctx, payload); err == nil {
		t.Fatal("zero-length ciphertext artifact accepted")
	}

	plaintext := encodeValues(ctx, values, 1, true)
	plaintext.values[0][0] = complex(math.Inf(1), 0)
	payload, err = writePlaintextPayload(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = readPlaintextPayload(ctx, payload); err == nil {
		t.Fatal("non-finite plaintext artifact accepted")
	}

	invalidShare := *share
	invalidShare.partyID = ""
	payload, err = writeSharePayload(&invalidShare)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = readSharePayload(ctx, payload); err == nil {
		t.Fatal("share with invalid participant accepted")
	}
	invalidShare = *share
	invalidShare.length = 0
	payload, err = writeSharePayload(&invalidShare)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = readSharePayload(ctx, payload); err == nil {
		t.Fatal("share with invalid logical length accepted")
	}

	contribution, err := generateEvalContribution(alice, true, []int{1}, true)
	if err != nil {
		t.Fatal(err)
	}
	contribution.rlin.ID = "wrong-owner"
	payload, err = writeEvalContributionPayload(contribution)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = readEvalContributionPayload(ctx, payload); err == nil {
		t.Fatal("relinearization key with wrong owner accepted")
	}
	contribution.rlin.ID = contribution.id
	contribution.rotations[1].RotIdx = 2
	payload, err = writeEvalContributionPayload(contribution)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = readEvalContributionPayload(ctx, payload); err == nil {
		t.Fatal("rotation key with inconsistent metadata accepted")
	}
	contribution.rotations[1].RotIdx = 1
	contribution.conj.ID = "wrong-owner"
	payload, err = writeEvalContributionPayload(contribution)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = readEvalContributionPayload(ctx, payload); err == nil {
		t.Fatal("conjugation key with wrong owner accepted")
	}
}

func TestConcurrentEvaluationKeyUse(t *testing.T) {
	ctx := testContext(t)
	ctx.workers = 2
	party, err := generateParty(ctx, "concurrent-evaluation-keys")
	if err != nil {
		t.Fatal(err)
	}
	values := [][]complex128{
		make([]complex128, ctx.params.Slots()),
		make([]complex128, ctx.params.Slots()),
	}
	values[0][0], values[1][0] = 0.25+0.5i, -0.5+0.25i
	ciphertext, err := encryptValues(ctx, party.pk, values, ctx.params.Slots()+1, true)
	if err != nil {
		t.Fatal(err)
	}
	contribution, err := generateEvalContribution(party, true, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := combineEvalContributions([]*nativeEvalContribution{contribution})
	if err != nil {
		t.Fatal(err)
	}

	errors := make(chan error, 4)
	var wait sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, multiplyErr := multiplyCipher(ciphertext, ciphertext, keys, false)
			errors <- multiplyErr
		}()
	}
	wait.Wait()
	close(errors)
	for multiplyErr := range errors {
		if multiplyErr != nil {
			t.Fatal(multiplyErr)
		}
	}
}

func mustArtifact(t *testing.T, entry registryEntry) []byte {
	t.Helper()
	data, err := serializeEntry(entry)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func requireStatusCode(t *testing.T, err error, want int) {
	t.Helper()
	var statusErr *nativeStatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("expected native status %d, got %T: %v", want, err, err)
	}
	if statusErr.code != want {
		t.Fatalf("unexpected native status: got %d want %d (%v)", statusErr.code, want, err)
	}
}

func TestCoreHelpersAndFailurePaths(t *testing.T) {
	ctx := testContext(t)
	other := testContext(t)
	if err := requireSameContext(ctx, other); err == nil {
		t.Fatal("different CRS contexts were treated as equal")
	}

	realValues := make([]float64, ctx.params.Slots()+1)
	imagValues := make([]float64, len(realValues))
	realValues[len(realValues)-1] = 3
	imagValues[len(imagValues)-1] = 4
	chunks := splitValues(ctx, realValues, imagValues, true)
	if len(chunks) != 2 || chunks[1][0] != 3+4i {
		t.Fatalf("unexpected split result: chunks=%d value=%v", len(chunks), chunks[1][0])
	}

	var calls atomic.Int32
	if err := parallelFor(8, 4, func(int) error { calls.Add(1); return nil }); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 8 {
		t.Fatalf("parallel worker lost calls: %d", calls.Load())
	}
	sentinel := errors.New("sentinel")
	if err := parallelFor(2, 2, func(i int) error {
		if i == 1 {
			return sentinel
		}
		return nil
	}); !errors.Is(err, sentinel) {
		t.Fatalf("parallel worker lost error: %v", err)
	}

	alice, err := generateParty(ctx, "helpers-alice")
	if err != nil {
		t.Fatal(err)
	}
	secretCopy := cloneSecretKey(alice.sk)
	zeroParty(&nativeParty{sk: secretCopy})
	for _, coefficients := range secretCopy.Value.Q.Coeffs {
		for _, coefficient := range coefficients {
			if coefficient != 0 {
				t.Fatal("secret-key coefficient was not overwritten")
			}
		}
	}

	polyBytes, err := serializePoly(alice.sk.Value.Q)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = deserializePoly(polyBytes); err != nil {
		t.Fatal(err)
	}
	buffer := new(bytes.Buffer)
	encodeLengthPrefixed(buffer, []byte("field"))
	if decoded, err := decodeLengthPrefixed(bytes.NewReader(buffer.Bytes()), 16); err != nil || string(decoded) != "field" {
		t.Fatalf("length-prefixed round trip failed: %q %v", decoded, err)
	}
	if _, err = decodeLengthPrefixed(bytes.NewReader(buffer.Bytes()), 2); err == nil {
		t.Fatal("oversized length-prefixed field accepted")
	}

	before := liveObjectCount()
	handle := putObject(kindPublicKey, &nativePublicKey{ctx: ctx, pk: alice.pk})
	if _, err = getAnyObject(handle); err != nil {
		t.Fatal(err)
	}
	if _, err = getObject(handle, kindCiphertext); err == nil {
		t.Fatal("wrong handle kind accepted")
	}
	if liveObjectCount() != before+1 {
		t.Fatal("live-object count did not increase")
	}
	if err = releaseObject(handle); err != nil {
		t.Fatal(err)
	}
	if _, err = getAnyObject(handle); err == nil {
		t.Fatal("released handle remained visible")
	}

	values := [][]complex128{make([]complex128, ctx.params.Slots())}
	values[0][0] = 1 + 0.5i
	ciphertext, err := encryptValues(ctx, alice.pk, values, 1, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = scalarCipher(ciphertext, 0.5+0.25i); err != nil {
		t.Fatal(err)
	}
	wrongPlaintext := encodeValues(other, values, 1, true)
	if _, err = addPlaintextCipher(ciphertext, wrongPlaintext, false); err == nil {
		t.Fatal("cross-context plaintext accepted")
	}
	if _, err = binaryCipher("invalid", ciphertext, ciphertext); err == nil {
		t.Fatal("unknown binary operation accepted")
	}
	share, err := partialDecrypt(alice, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = collectiveDecrypt(ciphertext, nil); err == nil {
		t.Fatal("missing share accepted")
	}
	wrongCiphertext := *ciphertext
	wrongCiphertext.artifact[0] ^= 1
	if _, err = collectiveDecrypt(&wrongCiphertext, []*nativeShare{share}); err == nil {
		t.Fatal("share bound to another ciphertext accepted")
	}

	contribution, err := generateEvalContribution(alice, true, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = combineEvalContributions([]*nativeEvalContribution{contribution, contribution}); err == nil {
		t.Fatal("duplicate evaluation contribution accepted")
	}
	bob, err := generateParty(ctx, "helpers-bob")
	if err != nil {
		t.Fatal(err)
	}
	bobCiphertext, err := encryptValues(ctx, bob.pk, values, 1, true)
	if err != nil {
		t.Fatal(err)
	}
	keyset, err := combineEvalContributions([]*nativeEvalContribution{contribution})
	if err != nil {
		t.Fatal(err)
	}
	if err = requireEvaluationCoverage(bobCiphertext, keyset); err == nil {
		t.Fatal("evaluation keys without participant coverage accepted")
	}

	if _, err = newContext([]byte("not-json"), 1); err == nil {
		t.Fatal("malformed parameter literal accepted")
	}
}

func TestParallelForSkipsQueuedWorkAfterFailure(t *testing.T) {
	const workers = 2
	var calls atomic.Int32
	ready := make(chan struct{})
	sentinel := errors.New("parallel failure")

	err := parallelFor(8, workers, func(int) error {
		// The first two jobs rendezvous before either fails. The dispatcher is
		// then blocked on the third unbuffered send; a worker can accept it only
		// after recording the failure, so it must be skipped deterministically.
		if calls.Add(1) == workers {
			close(ready)
		}
		<-ready
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("parallel worker lost error: %v", err)
	}
	if got := calls.Load(); got != workers {
		t.Fatalf("queued work ran after failure: got %d calls want %d", got, workers)
	}
}

func TestStrictParameterAndOperationValidation(t *testing.T) {
	ctx := testContext(t)
	valid, err := json.Marshal(ctx.literal)
	if err != nil {
		t.Fatal(err)
	}
	invalidLiterals := [][]byte{
		nil,
		make([]byte, (1<<20)+1),
		[]byte(`[]`),
		[]byte(`{"log_n":14}`),
		[]byte(`{"log_n":14,"log_n":15,"log_slots":13,"q":[17],"p":[19,23],"scale":2,"sigma":3.2}`),
		[]byte(`{"log_n":14,"log_slots":13,"q":[17],"p":[19,23],"scale":2,"sigma":3.2,"unknown":1}`),
		append(append([]byte{}, valid...), []byte(` {}`)...),
	}
	for _, literal := range invalidLiterals {
		if _, createErr := newContext(literal, 1); createErr == nil {
			t.Fatalf("invalid literal accepted: %.80q", literal)
		}
	}
	bad := ctx.literal
	bad.LogSlots = bad.LogN
	raw, _ := json.Marshal(bad)
	if _, err = newContext(raw, 1); err == nil {
		t.Fatal("invalid slot exponent accepted")
	}
	bad = ctx.literal
	bad.P = bad.P[:1]
	raw, _ = json.Marshal(bad)
	if _, err = newContext(raw, 1); err == nil {
		t.Fatal("insufficient P moduli accepted")
	}
	bad = ctx.literal
	bad.Scale = math.Inf(1)
	raw, _ = json.Marshal(bad)
	if _, err = newContext(raw, 1); err == nil {
		t.Fatal("non-finite scale accepted")
	}
	if _, err = newContext(valid, -1); err == nil {
		t.Fatal("negative worker count accepted")
	}
	if automatic, automaticErr := newContext(valid, 0); automaticErr != nil || automatic.workers < 1 {
		t.Fatalf("automatic worker selection failed: %v", automaticErr)
	}

	for _, test := range []struct {
		left, right float64
		want        bool
	}{
		{1, 1, true}, {1, 1.0000001, true}, {1, 2, true},
		{1, 1.5, false}, {math.Inf(1), 1, false}, {1, 1 << 54, false},
	} {
		if got := compatibleScales(test.left, test.right); got != test.want {
			t.Fatalf("compatibleScales(%g, %g)=%v want %v", test.left, test.right, got, test.want)
		}
	}

	for _, id := range []string{"nul\x00id", string([]byte{0xff}), string(make([]byte, 129))} {
		if _, err = generateParty(ctx, id); err == nil {
			t.Fatalf("invalid party ID accepted: %q", id)
		}
	}
	alice, err := generateParty(ctx, "strict-alice")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := generateParty(ctx, "strict-bob")
	if err != nil {
		t.Fatal(err)
	}
	values := [][]complex128{make([]complex128, ctx.params.Slots())}
	values[0][0] = 0.25 + 0.125i
	ciphertext, err := encryptValues(ctx, alice.pk, values, 1, true)
	if err != nil {
		t.Fatal(err)
	}
	mismatched := *ciphertext
	mismatched.length++
	if _, err = binaryCipher("add", ciphertext, &mismatched); err == nil {
		t.Fatal("mismatched ciphertext length accepted")
	}
	if _, err = multiplyCipher(ciphertext, &mismatched, nil, false); err == nil {
		t.Fatal("mismatched ciphertext multiplication accepted")
	} else {
		requireStatusCode(t, err, statusInvalid)
	}
	badScale := *ciphertext
	badScale.chunks = []*mkckks.Ciphertext{ciphertext.chunks[0].CopyNew()}
	badScale.chunks[0].Scale *= 1.5
	if _, err = binaryCipher("add", ciphertext, &badScale); err == nil {
		t.Fatal("incompatible scales accepted")
	}
	if _, err = scalarCipher(ciphertext, complex(math.NaN(), 0)); err == nil {
		t.Fatal("non-finite scalar accepted")
	}
	plaintext := encodeValues(ctx, values, 1, true)
	wrongPlaintext := *plaintext
	wrongPlaintext.length++
	if _, err = addPlaintextCipher(ciphertext, &wrongPlaintext, false); err == nil {
		t.Fatal("mismatched plaintext addition accepted")
	}
	if _, err = plaintextCipher(ciphertext, &wrongPlaintext); err == nil {
		t.Fatal("mismatched plaintext multiplication accepted")
	}
	levelZero, err := levelCipher(ciphertext, "drop", float64(ciphertext.chunks[0].Level()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = plaintextCipher(levelZero, plaintext); err == nil {
		t.Fatal("level-zero plaintext multiplication accepted")
	}
	if _, err = levelCipher(levelZero, "rescale", ctx.params.Scale()); err == nil {
		t.Fatal("level-zero rescale accepted")
	}
	if _, err = levelCipher(ciphertext, "rescale", math.SmallestNonzeroFloat64); err == nil {
		t.Fatal("exhausting rescale threshold accepted")
	}
	scaleContribution, err := generateEvalContribution(alice, true, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	scaleKeys, err := combineEvalContributions([]*nativeEvalContribution{scaleContribution})
	if err != nil {
		t.Fatal(err)
	}
	productForScale, err := multiplyCipher(ciphertext, ciphertext, scaleKeys, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = levelCipher(productForScale, "rescale", 1); err == nil {
		t.Fatal("rescale producing an unsupported scale accepted")
	}

	contribution, err := generateEvalContribution(alice, false, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := combineEvalContributions([]*nativeEvalContribution{contribution})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = multiplyCipher(ciphertext, ciphertext, keys, false); err == nil {
		t.Fatal("missing relinearization key accepted")
	}
	if _, err = multiplyCipher(levelZero, levelZero, keys, false); err == nil {
		t.Fatal("level-zero ciphertext multiplication accepted")
	}
	if _, err = rotateCipher(ciphertext, keys, 1, false); err == nil {
		t.Fatal("missing rotation key accepted")
	}
	if _, err = conjugateCipher(ciphertext, keys); err == nil {
		t.Fatal("missing conjugation key accepted")
	}
	bobCiphertext, err := encryptValues(ctx, bob.pk, values, 1, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = partialDecrypt(alice, bobCiphertext); err == nil {
		t.Fatal("non-participant decryption share accepted")
	} else {
		requireStatusCode(t, err, statusShare)
	}
	share, err := partialDecrypt(alice, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	wrongLevelShare := *share
	wrongLevelShare.deltas = []*ring.Poly{share.deltas[0].CopyNew()}
	wrongLevelShare.deltas[0].Coeffs = wrongLevelShare.deltas[0].Coeffs[:1]
	if _, err = collectiveDecrypt(ciphertext, []*nativeShare{&wrongLevelShare}); err == nil {
		t.Fatal("wrong-level decryption share accepted")
	}
}

func TestNativeEnvelopeValidationMatrix(t *testing.T) {
	checksummed := func(body []byte) []byte {
		digest := sha256.Sum256(body)
		return append(append([]byte{}, body...), digest[:]...)
	}
	envelope := func(magic [8]byte, major, minor uint16, abi uint32, commit string, trailing bool) []byte {
		w := new(binaryWriter)
		w.raw(magic[:])
		w.u16(major)
		w.u16(minor)
		w.u8(uint8(kindPlaintext))
		w.u32(abi)
		w.string(commit)
		w.string("fingerprint")
		w.bytes([]byte("payload"))
		if trailing {
			w.u8(1)
		}
		return checksummed(w.Bytes())
	}

	invalidMagic := artifactMagic
	invalidMagic[0] ^= 1
	for _, artifact := range [][]byte{
		[]byte("short"),
		envelope(invalidMagic, artifactMajor, artifactMinor, abiVersion, upstreamCommit, false),
		envelope(artifactMagic, artifactMajor+1, artifactMinor, abiVersion, upstreamCommit, false),
		envelope(artifactMagic, artifactMajor, artifactMinor+1, abiVersion, upstreamCommit, false),
		envelope(artifactMagic, artifactMajor, artifactMinor, abiVersion+1, upstreamCommit, false),
		envelope(artifactMagic, artifactMajor, artifactMinor, abiVersion, "wrong", false),
		envelope(artifactMagic, artifactMajor, artifactMinor, abiVersion, upstreamCommit, true),
	} {
		if _, _, _, err := unwrapArtifact(artifact); err == nil {
			t.Fatal("invalid native envelope accepted")
		}
	}
	valid, err := wrapArtifact(kindPlaintext, "fingerprint", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	valid[len(valid)-1] ^= 1
	if _, _, _, err = unwrapArtifact(valid); err == nil {
		t.Fatal("checksum corruption accepted")
	}

	r := newBinaryReader([]byte{0, 0, 0, 0, 0, 0, 1, 0})
	if value := r.bytes(8); value != nil || r.done() == nil {
		t.Fatal("oversized field length accepted")
	}
	r = newBinaryReader([]byte{1})
	if err = r.done(); err == nil {
		t.Fatal("trailing reader byte accepted")
	}
	if _, err = serializeEntry(registryEntry{kind: objectKind(255)}); err == nil {
		t.Fatal("unsupported registry kind serialized")
	}
	ctx := testContext(t)
	unknown, err := wrapArtifact(objectKind(255), ctx.fingerprint, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = deserializeEntry(ctx, unknown); err == nil {
		t.Fatal("unsupported registry kind deserialized")
	}
	wrongContext, err := wrapArtifact(kindPlaintext, "wrong", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = deserializeEntry(ctx, wrongContext); err == nil {
		t.Fatal("wrong-context artifact accepted")
	}
}

func TestPayloadDecoderAllocationAndStructureBounds(t *testing.T) {
	ctx := testContext(t)
	literal, _ := json.Marshal(ctx.literal)
	w := new(binaryWriter)
	w.bytes(literal)
	w.u32(1)
	w.u32((1 << 16) + 1)
	if _, err := readContextPayload(w.Bytes()); err == nil {
		t.Fatal("oversized CRS count accepted")
	}

	w = new(binaryWriter)
	w.u64(1)
	w.u8(0)
	w.u32(0)
	if _, err := readPlaintextPayload(ctx, w.Bytes()); err == nil {
		t.Fatal("zero plaintext chunk count accepted")
	}
	w = new(binaryWriter)
	w.u64(1)
	w.u8(0)
	w.u32(1)
	w.u32(1)
	if _, err := readPlaintextPayload(ctx, w.Bytes()); err == nil {
		t.Fatal("wrong plaintext slot count accepted")
	}
	values := [][]complex128{make([]complex128, ctx.params.Slots())}
	plaintext := encodeValues(ctx, values, 1, false)
	validPlaintext, err := writePlaintextPayload(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = readPlaintextPayload(ctx, append(validPlaintext, 0)); err == nil {
		t.Fatal("trailing plaintext byte accepted")
	}
	wrongLengthPlaintext := *plaintext
	wrongLengthPlaintext.length = ctx.params.Slots() + 1
	payload, _ := writePlaintextPayload(&wrongLengthPlaintext)
	if _, err = readPlaintextPayload(ctx, payload); err == nil {
		t.Fatal("inconsistent plaintext logical length accepted")
	}

	w = new(binaryWriter)
	w.string("alice")
	w.raw(make([]byte, 16))
	w.u64(1)
	w.u32(0)
	if _, err = readSharePayload(ctx, w.Bytes()); err == nil {
		t.Fatal("zero decryption-share chunk count accepted")
	}

	w = new(binaryWriter)
	w.u64(1)
	w.u8(0)
	w.raw(make([]byte, 16))
	w.u32(0)
	if _, err = readCipherPayload(ctx, w.Bytes()); err == nil {
		t.Fatal("zero ciphertext chunk count accepted")
	}
	w = new(binaryWriter)
	w.u64(1)
	w.u8(0)
	w.raw(make([]byte, 16))
	w.u32(1)
	w.f64(math.Inf(1))
	if _, err = readCipherPayload(ctx, w.Bytes()); err == nil {
		t.Fatal("non-finite ciphertext scale accepted")
	}
	w = new(binaryWriter)
	w.u64(1)
	w.u8(0)
	w.raw(make([]byte, 16))
	w.u32(1)
	w.f64(ctx.params.Scale())
	w.u32(0)
	if _, err = readCipherPayload(ctx, w.Bytes()); err == nil {
		t.Fatal("zero ciphertext component count accepted")
	}
	party, err := generateParty(ctx, "payload-bounds-party")
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := encryptValues(ctx, party.pk, values, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	validCiphertext, _ := writeCipherPayload(ciphertext)
	if _, err = readCipherPayload(ctx, append(validCiphertext, 0)); err == nil {
		t.Fatal("trailing ciphertext byte accepted")
	}
	wrongLengthCiphertext := *ciphertext
	wrongLengthCiphertext.length = ctx.params.Slots() + 1
	payload, _ = writeCipherPayload(&wrongLengthCiphertext)
	if _, err = readCipherPayload(ctx, payload); err == nil {
		t.Fatal("inconsistent ciphertext logical length accepted")
	}
	share, err := partialDecrypt(party, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	validShare, _ := writeSharePayload(share)
	if _, err = readSharePayload(ctx, append(validShare, 0)); err == nil {
		t.Fatal("trailing share byte accepted")
	}
	wrongLengthShare := *share
	wrongLengthShare.length = ctx.params.Slots() + 1
	payload, _ = writeSharePayload(&wrongLengthShare)
	if _, err = readSharePayload(ctx, payload); err == nil {
		t.Fatal("inconsistent share logical length accepted")
	}
	publicPayload, _ := writePublicKeyPayload(&nativePublicKey{ctx: ctx, pk: party.pk})
	if _, err = readPublicKeyPayload(ctx, append(publicPayload, 0)); err == nil {
		t.Fatal("trailing public-key byte accepted")
	}
	contribution, err := generateEvalContribution(party, false, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	contributionPayload, _ := writeEvalContributionPayload(contribution)
	if _, err = readEvalContributionPayload(ctx, append(contributionPayload, 0)); err == nil {
		t.Fatal("trailing evaluation contribution byte accepted")
	}
	keyset, err := combineEvalContributions([]*nativeEvalContribution{contribution})
	if err != nil {
		t.Fatal(err)
	}
	keysetPayload, _ := writeEvalSetPayload(keyset)
	if _, err = readEvalSetPayload(ctx, append(keysetPayload, 0)); err == nil {
		t.Fatal("trailing evaluation-key-set byte accepted")
	}

	w = new(binaryWriter)
	w.string("alice")
	writeRelinearizationKey(w, nil)
	w.u32((1 << 16) + 1)
	if _, err = readEvalContributionPayload(ctx, w.Bytes()); err == nil {
		t.Fatal("oversized rotation-key count accepted")
	}
	w = new(binaryWriter)
	w.u32(0)
	if _, err = readEvalSetPayload(ctx, w.Bytes()); err == nil {
		t.Fatal("zero evaluation participant count accepted")
	}
}

func TestCorrectnessTrackingRangeAndArtifactRoundTrip(t *testing.T) {
	ctx := testContext(t)
	party, err := generateParty(ctx, "tracking-party")
	if err != nil {
		t.Fatal(err)
	}
	values := [][]complex128{make([]complex128, ctx.params.Slots())}
	values[0][0] = 2
	ciphertext, err := encryptValues(ctx, party.pk, values, 1, false)
	if err != nil {
		t.Fatal(err)
	}
	if ciphertext.tracking.rangeExceeded || ciphertext.tracking.magnitudeBound < 2 {
		t.Fatalf("fresh ciphertext has invalid tracking: %+v", ciphertext.tracking)
	}
	contribution, err := generateEvalContribution(party, true, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := combineEvalContributions([]*nativeEvalContribution{contribution})
	if err != nil {
		t.Fatal(err)
	}
	transitions := 0
	for ciphertext.chunks[0].Level() > 0 {
		previousExceeded := ciphertext.tracking.rangeExceeded
		ciphertext, err = multiplyCipher(ciphertext, ciphertext, keys, false)
		if err != nil {
			t.Fatal(err)
		}
		if !previousExceeded && ciphertext.tracking.rangeExceeded {
			transitions++
		}
	}
	if transitions != 1 || !ciphertext.tracking.rangeExceeded ||
		trackedRangeMargin(ctx, ciphertext.chunks[0].Level(), ciphertext.chunks[0].Scale, ciphertext.tracking) >= 0 {
		t.Fatalf("expected one sticky range transition, got %d and %+v", transitions, ciphertext.tracking)
	}
	zeroed, err := scalarCipher(ciphertext, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !zeroed.tracking.rangeExceeded || zeroed.tracking.magnitudeBound != 0 {
		t.Fatalf("zero multiplication cleared sticky range state: %+v", zeroed.tracking)
	}
	artifact, err := serializeEntry(registryEntry{kind: kindCiphertext, value: zeroed})
	if err != nil {
		t.Fatal(err)
	}
	entry, err := deserializeEntry(ctx, artifact)
	if err != nil {
		t.Fatal(err)
	}
	restored := entry.value.(*nativeCiphertext)
	if restored.tracking != zeroed.tracking {
		t.Fatalf("tracking changed across artifact: got %+v want %+v", restored.tracking, zeroed.tracking)
	}

	plaintext := encodeValues(ctx, values, 1, false)
	if plaintext.tracking.magnitudeBound < 2 || plaintext.tracking.errorBound <= 0 {
		t.Fatalf("plaintext tracking is invalid: %+v", plaintext.tracking)
	}
	plainArtifact, err := serializeEntry(registryEntry{kind: kindPlaintext, value: plaintext})
	if err != nil {
		t.Fatal(err)
	}
	plainEntry, err := deserializeEntry(ctx, plainArtifact)
	if err != nil {
		t.Fatal(err)
	}
	if plainEntry.value.(*nativePlaintext).tracking != plaintext.tracking {
		t.Fatal("plaintext tracking changed across artifact")
	}

	if boundedMultiply(math.MaxFloat64, 2) != math.MaxFloat64 ||
		boundedAdd(math.MaxFloat64, 1) != math.MaxFloat64 {
		t.Fatal("tracking arithmetic did not saturate")
	}
}

func TestRescalePlannerEveryModulusBoundary(t *testing.T) {
	for _, preset := range []string{"PN14QP439", "PN15QP880"} {
		t.Run(preset, func(t *testing.T) {
			ctx := differentialContext(t, preset)
			baseScale := ctx.params.Scale()
			for level := 1; level <= ctx.params.MaxLevel(); level++ {
				syntheticScale := baseScale
				for consumedTarget := 0; consumedTarget <= level; consumedTarget++ {
					if consumedTarget > 0 {
						syntheticScale *= float64(ctx.params.Q()[level-consumedTarget+1])
					}
					if math.IsInf(syntheticScale, 0) {
						t.Fatalf("synthetic scale overflow at level=%d consumed=%d", level, consumedTarget)
					}
					postTargetScale := syntheticScale
					for index := 0; index < consumedTarget; index++ {
						postTargetScale /= float64(ctx.params.Q()[level-index])
					}
					boundary := 2 * postTargetScale / float64(ctx.params.Q()[level-consumedTarget])
					high := math.Nextafter(boundary, math.Inf(1))
					consumed, resultScale, err := rescalePlan(ctx, level, syntheticScale, high)
					if err != nil {
						t.Fatalf("high-side boundary rejected at level=%d consumed=%d: %v", level, consumedTarget, err)
					}
					if consumed != consumedTarget || resultScale < baseScale/2 {
						t.Fatalf(
							"high-side boundary mismatch at level=%d: got consumed=%d scale=%.17g want=%d",
							level, consumed, resultScale, consumedTarget,
						)
					}
					low := math.Nextafter(boundary, math.Inf(-1))
					if _, _, err = rescalePlan(ctx, level, syntheticScale, low); err == nil {
						t.Fatalf("low-side boundary unexpectedly accepted at level=%d consumed=%d", level, consumedTarget)
					}
				}
			}
		})
	}
}

func TestArtifactDecoderValidationMatrix(t *testing.T) {
	ctx := testContext(t)
	party, err := generateParty(ctx, "decoder-matrix-alice")
	if err != nil {
		t.Fatal(err)
	}
	values := [][]complex128{
		make([]complex128, ctx.params.Slots()),
		make([]complex128, ctx.params.Slots()),
	}
	values[0][0], values[1][0] = 0.25+0.5i, -0.75+0.125i
	ciphertext, err := encryptValues(ctx, party.pk, values, ctx.params.Slots()+1, true)
	if err != nil {
		t.Fatal(err)
	}
	share, err := partialDecrypt(party, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	contribution, err := generateEvalContribution(party, true, []int{1}, true)
	if err != nil {
		t.Fatal(err)
	}

	requireRejected := func(name string, err error) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}

	t.Run("polynomial and key validation", func(t *testing.T) {
		w := new(binaryWriter)
		writeSwitchingKey(w, nil)
		r := newBinaryReader(w.Bytes())
		if readSwitchingKey(r) != nil || r.done() != nil {
			t.Fatal("nil switching key did not round-trip")
		}

		w = new(binaryWriter)
		w.u8(1)
		w.u32((1 << 16) + 1)
		r = newBinaryReader(w.Bytes())
		if readSwitchingKey(r) != nil || r.done() == nil {
			t.Fatal("oversized switching-key decomposition was accepted")
		}

		badQP := party.sk.Value.CopyNew()
		badQP.Q.Coeffs = nil
		requireRejected("Q-less PolyQP", validatePolyQP(ctx, badQP))

		relinearization := contribution.rlin
		originalID := relinearization.ID
		relinearization.ID = ""
		requireRejected("relinearization key with invalid owner", validateRelinearizationKey(ctx, relinearization))
		relinearization.ID = originalID

		switching := relinearization.Value[0]
		originalQ := switching.Value[0].Q
		wrongDegree := originalQ.CopyNew()
		wrongDegree.Coeffs[0] = wrongDegree.Coeffs[0][:1]
		switching.Value[0].Q = wrongDegree
		requireRejected("relinearization key with invalid switching polynomial", validateRelinearizationKey(ctx, relinearization))
		switching.Value[0].Q = originalQ

		rotation := contribution.rotations[1]
		rotationID, rotationIndex := rotation.ID, rotation.RotIdx
		rotation.ID = ""
		requireRejected("rotation key with invalid owner", validateRotationKey(ctx, rotation))
		rotation.ID = rotationID
		rotation.RotIdx = 0
		requireRejected("zero rotation key index", validateRotationKey(ctx, rotation))
		rotation.RotIdx = uint(ctx.params.Slots())
		requireRejected("out-of-range rotation key index", validateRotationKey(ctx, rotation))
		rotation.RotIdx = rotationIndex
		originalQ = rotation.Value.Value[0].Q
		wrongDegree = originalQ.CopyNew()
		wrongDegree.Coeffs[0] = wrongDegree.Coeffs[0][:1]
		rotation.Value.Value[0].Q = wrongDegree
		requireRejected("rotation key with invalid switching polynomial", validateRotationKey(ctx, rotation))
		rotation.Value.Value[0].Q = originalQ

		conjugation := contribution.conj
		conjugationID := conjugation.ID
		conjugation.ID = ""
		requireRejected("conjugation key with invalid owner", validateConjugationKey(ctx, conjugation))
		conjugation.ID = conjugationID
		originalQ = conjugation.Value.Value[0].Q
		wrongDegree = originalQ.CopyNew()
		wrongDegree.Coeffs[0] = wrongDegree.Coeffs[0][:1]
		conjugation.Value.Value[0].Q = wrongDegree
		requireRejected("conjugation key with invalid switching polynomial", validateConjugationKey(ctx, conjugation))
		conjugation.Value.Value[0].Q = originalQ
	})

	cloneCiphertext := func() *nativeCiphertext {
		clone := *ciphertext
		clone.chunks = make([]*mkckks.Ciphertext, len(ciphertext.chunks))
		for i, chunk := range ciphertext.chunks {
			clone.chunks[i] = chunk.CopyNew()
		}
		return &clone
	}
	decodeCiphertext := func(value *nativeCiphertext) error {
		payload, writeErr := writeCipherPayload(value)
		if writeErr != nil {
			return writeErr
		}
		_, readErr := readCipherPayload(ctx, payload)
		return readErr
	}

	t.Run("ciphertext consistency", func(t *testing.T) {
		invalid := cloneCiphertext()
		invalid.chunks[1].Scale *= 2
		requireRejected("inconsistent ciphertext scales", decodeCiphertext(invalid))

		invalid = cloneCiphertext()
		delete(invalid.chunks[1].Value, party.sk.ID)
		requireRejected("inconsistent ciphertext participants", decodeCiphertext(invalid))

		invalid = cloneCiphertext()
		invalid.chunks[1].Value["0"].Coeffs = invalid.chunks[1].Value["0"].Coeffs[:len(invalid.chunks[1].Value["0"].Coeffs)-1]
		requireRejected("inconsistent ciphertext levels", decodeCiphertext(invalid))

		invalid = cloneCiphertext()
		delete(invalid.chunks[0].Value, "0")
		requireRejected("ciphertext missing component zero", decodeCiphertext(invalid))

		invalid = cloneCiphertext()
		invalid.chunks[0].Value[""] = invalid.chunks[0].Value[party.sk.ID].CopyNew()
		requireRejected("ciphertext with invalid participant", decodeCiphertext(invalid))

		invalid = cloneCiphertext()
		invalid.tracking.magnitudeBound = math.MaxFloat64
		invalid.tracking.rangeExceeded = false
		requireRejected("ciphertext with inconsistent range metadata", decodeCiphertext(invalid))
	})

	t.Run("share consistency", func(t *testing.T) {
		invalid := *share
		invalid.deltas = make([]*ring.Poly, len(share.deltas))
		for i, delta := range share.deltas {
			invalid.deltas[i] = delta.CopyNew()
		}
		invalid.deltas[1].Coeffs = invalid.deltas[1].Coeffs[:len(invalid.deltas[1].Coeffs)-1]
		payload, writeErr := writeSharePayload(&invalid)
		if writeErr != nil {
			t.Fatal(writeErr)
		}
		_, readErr := readSharePayload(ctx, payload)
		requireRejected("share chunks with inconsistent levels", readErr)
	})

	t.Run("party plaintext and primitive payloads", func(t *testing.T) {
		partyPayload, writeErr := writePartyPayload(party)
		if writeErr != nil {
			t.Fatal(writeErr)
		}
		_, readErr := readPartyPayload(ctx, partyPayload)
		requireRejected("duplicate imported party", readErr)

		badPublic := &nativePublicKey{ctx: ctx, pk: clonePublicKey(party.pk)}
		badPublic.pk.Value[0].Q.Coeffs[0] = badPublic.pk.Value[0].Q.Coeffs[0][:1]
		publicPayload, writeErr := writePublicKeyPayload(badPublic)
		if writeErr != nil {
			t.Fatal(writeErr)
		}
		_, readErr = readPublicKeyPayload(ctx, publicPayload)
		requireRejected("public key with invalid polynomial degree", readErr)

		plaintext := encodeValues(ctx, values, ctx.params.Slots()+1, true)
		plaintext.tracking.magnitudeBound++
		plaintextPayload, writeErr := writePlaintextPayload(plaintext)
		if writeErr != nil {
			t.Fatal(writeErr)
		}
		_, readErr = readPlaintextPayload(ctx, plaintextPayload)
		requireRejected("plaintext with inconsistent correctness metadata", readErr)

		w := new(binaryWriter)
		w.bytes([]byte("not-a-polynomial"))
		r := newBinaryReader(w.Bytes())
		if readPoly(r) != nil || r.done() == nil {
			t.Fatal("malformed serialized polynomial was accepted")
		}
		if _, readErr = deserializePoly([]byte("not-a-polynomial")); readErr == nil {
			t.Fatal("malformed polynomial bytes were accepted")
		}
		validPolyBytes, marshalErr := serializePoly(share.deltas[0])
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if _, readErr = deserializePoly(validPolyBytes); readErr != nil {
			t.Fatalf("valid polynomial bytes were rejected: %v", readErr)
		}
		polyHeaderCases := []struct {
			name string
			data []byte
		}{
			{name: "empty", data: nil},
			{name: "truncated header", data: []byte{14, 1, 0}},
			{name: "log n below context minimum", data: []byte{3, 1, 0, 0}},
			{name: "log n above context maximum", data: []byte{21, 1, 0, 0}},
			{name: "zero moduli", data: []byte{14, 0, 0, 0}},
			{name: "invalid ntt flag", data: []byte{14, 1, 2, 0}},
			{name: "invalid montgomery flag", data: []byte{14, 1, 0, 2}},
			{name: "truncated coefficients", data: []byte{14, 1, 0, 0}},
			{name: "declared size above artifact limit", data: []byte{20, 255, 0, 0}},
		}
		for _, test := range polyHeaderCases {
			t.Run(test.name, func(t *testing.T) {
				if _, err := deserializePoly(test.data); err == nil {
					t.Fatal("malformed polynomial header was accepted")
				}
			})
		}
		if _, readErr = decodeLengthPrefixed(bytes.NewReader([]byte{0, 1}), 16); readErr == nil {
			t.Fatal("truncated length prefix was accepted")
		}
	})

	t.Run("evaluation key ownership and duplication", func(t *testing.T) {
		writeParticipant := func(w *binaryWriter, id string, rotations int) {
			w.string(id)
			writeRelinearizationKey(w, nil)
			w.u32(uint32(rotations))
			for i := 0; i < rotations; i++ {
				writeRotationKey(w, contribution.rotations[1])
			}
			writeConjugationKey(w, nil)
		}

		w := new(binaryWriter)
		w.u32(2)
		writeParticipant(w, party.sk.ID, 0)
		writeParticipant(w, party.sk.ID, 0)
		_, readErr := readEvalSetPayload(ctx, w.Bytes())
		requireRejected("duplicate evaluation-key participant", readErr)

		w = new(binaryWriter)
		w.u32(1)
		writeParticipant(w, party.sk.ID, 2)
		_, readErr = readEvalSetPayload(ctx, w.Bytes())
		requireRejected("duplicate evaluation-key rotation", readErr)

		w = new(binaryWriter)
		w.u32(1)
		w.string(party.sk.ID)
		originalID := contribution.rlin.ID
		contribution.rlin.ID = "another-owner"
		writeRelinearizationKey(w, contribution.rlin)
		contribution.rlin.ID = originalID
		w.u32(0)
		writeConjugationKey(w, nil)
		_, readErr = readEvalSetPayload(ctx, w.Bytes())
		requireRejected("relinearization-key participant mismatch", readErr)

		w = new(binaryWriter)
		w.u32(1)
		w.string(party.sk.ID)
		writeRelinearizationKey(w, nil)
		w.u32(1)
		rotation := contribution.rotations[1]
		originalID = rotation.ID
		rotation.ID = "another-owner"
		writeRotationKey(w, rotation)
		rotation.ID = originalID
		writeConjugationKey(w, nil)
		_, readErr = readEvalSetPayload(ctx, w.Bytes())
		requireRejected("rotation-key participant mismatch", readErr)

		w = new(binaryWriter)
		w.u32(1)
		w.string(party.sk.ID)
		writeRelinearizationKey(w, nil)
		w.u32(0)
		conjugation := contribution.conj
		originalID = conjugation.ID
		conjugation.ID = "another-owner"
		writeConjugationKey(w, conjugation)
		conjugation.ID = originalID
		_, readErr = readEvalSetPayload(ctx, w.Bytes())
		requireRejected("conjugation-key participant mismatch", readErr)

		w = new(binaryWriter)
		w.u32(1)
		w.string(party.sk.ID)
		writeRelinearizationKey(w, nil)
		w.u32((1 << 16) + 1)
		_, readErr = readEvalSetPayload(ctx, w.Bytes())
		requireRejected("oversized evaluation-key rotation count", readErr)

		w = new(binaryWriter)
		w.string(party.sk.ID)
		writeRelinearizationKey(w, nil)
		w.u32(1)
		w.i64(0)
		_, readErr = readEvalContributionPayload(ctx, w.Bytes())
		requireRejected("zero contribution rotation index", readErr)

		w = new(binaryWriter)
		w.string(party.sk.ID)
		writeRelinearizationKey(w, nil)
		w.u32(2)
		for i := 0; i < 2; i++ {
			w.i64(1)
			writeRotationKey(w, contribution.rotations[1])
		}
		writeConjugationKey(w, nil)
		_, readErr = readEvalContributionPayload(ctx, w.Bytes())
		requireRejected("duplicate contribution rotation", readErr)

		w = new(binaryWriter)
		w.u32(1)
		writeParticipant(w, "", 0)
		_, readErr = readEvalSetPayload(ctx, w.Bytes())
		requireRejected("evaluation set with invalid participant", readErr)

		w = new(binaryWriter)
		w.u32(1)
		w.string(party.sk.ID)
		originalID = contribution.rlin.ID
		contribution.rlin.ID = ""
		writeRelinearizationKey(w, contribution.rlin)
		contribution.rlin.ID = originalID
		w.u32(0)
		writeConjugationKey(w, nil)
		_, readErr = readEvalSetPayload(ctx, w.Bytes())
		requireRejected("evaluation set with invalid relinearization key", readErr)

		w = new(binaryWriter)
		w.u32(1)
		w.string(party.sk.ID)
		writeRelinearizationKey(w, nil)
		w.u32(1)
		rotation = contribution.rotations[1]
		originalIndex := rotation.RotIdx
		rotation.RotIdx = 0
		writeRotationKey(w, rotation)
		rotation.RotIdx = originalIndex
		writeConjugationKey(w, nil)
		_, readErr = readEvalSetPayload(ctx, w.Bytes())
		requireRejected("evaluation set with invalid rotation key", readErr)

		w = new(binaryWriter)
		w.u32(1)
		w.string(party.sk.ID)
		writeRelinearizationKey(w, nil)
		w.u32(0)
		conjugation = contribution.conj
		originalID = conjugation.ID
		conjugation.ID = ""
		writeConjugationKey(w, conjugation)
		conjugation.ID = originalID
		_, readErr = readEvalSetPayload(ctx, w.Bytes())
		requireRejected("evaluation set with invalid conjugation key", readErr)
	})
}

func TestModelFailureAtomicityMatrix(t *testing.T) {
	ctx := testContext(t)
	other := testContext(t)
	alice, err := generateParty(ctx, "failure-matrix-alice")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := generateParty(ctx, "failure-matrix-bob")
	if err != nil {
		t.Fatal(err)
	}
	values := [][]complex128{make([]complex128, ctx.params.Slots())}
	values[0][0] = 0.5 + 0.25i
	aliceCiphertext, err := encryptValues(ctx, alice.pk, values, 1, true)
	if err != nil {
		t.Fatal(err)
	}
	bobCiphertext, err := encryptValues(ctx, bob.pk, values, 1, true)
	if err != nil {
		t.Fatal(err)
	}
	combined, err := binaryCipher("add", aliceCiphertext, bobCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	aliceShare, err := partialDecrypt(alice, combined)
	if err != nil {
		t.Fatal(err)
	}
	bobShare, err := partialDecrypt(bob, combined)
	if err != nil {
		t.Fatal(err)
	}

	assertRejected := func(name string, err error) {
		t.Helper()
		if err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}

	validLiteral, err := json.Marshal(ctx.literal)
	if err != nil {
		t.Fatal(err)
	}
	_, err = newContext(validLiteral, 1025)
	assertRejected("excessive worker count", err)
	zeroParty(nil)
	zeroParty(&nativeParty{})
	secretWithNilP := cloneSecretKey(alice.sk)
	secretWithNilP.Value.P = nil
	zeroParty(&nativeParty{sk: secretWithNilP})
	if boundedAdd(-1) != math.MaxFloat64 ||
		boundedMultiply(-1, 1) != math.MaxFloat64 ||
		boundedMultiply(0, 1) != 0 ||
		primitiveErrorBound(ctx, 0, 8) != math.MaxFloat64 ||
		primitiveErrorBound(ctx, ctx.params.Scale(), math.Inf(1)) != math.MaxFloat64 {
		t.Fatal("bounded numerical helpers accepted invalid inputs")
	}

	wrongContextShare := *aliceShare
	wrongContextShare.ctx = other
	_, err = collectiveDecrypt(combined, []*nativeShare{&wrongContextShare, bobShare})
	assertRejected("wrong-context share", err)

	unexpectedShare := *aliceShare
	unexpectedShare.partyID = "unexpected-party"
	_, err = collectiveDecrypt(combined, []*nativeShare{&unexpectedShare, bobShare})
	assertRejected("unexpected share", err)

	_, err = collectiveDecrypt(combined, []*nativeShare{aliceShare, aliceShare})
	assertRejected("duplicate share", err)

	wrongBinding := *aliceShare
	wrongBinding.length++
	_, err = collectiveDecrypt(combined, []*nativeShare{&wrongBinding, bobShare})
	assertRejected("share with wrong logical length", err)

	keysContribution, err := generateEvalContribution(alice, true, []int{1}, true)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := combineEvalContributions([]*nativeEvalContribution{keysContribution})
	if err != nil {
		t.Fatal(err)
	}
	keys.ctx = other
	assertRejected("wrong-context evaluation keys", requireEvaluationCoverage(aliceCiphertext, keys))
	keys.ctx = ctx
	_, err = multiplyCipher(aliceCiphertext, bobCiphertext, keys, false)
	assertRejected("multiplication without all participant keys", err)
	mismatched := *aliceCiphertext
	mismatched.length++
	_, err = multiplyCipher(aliceCiphertext, &mismatched, keys, false)
	assertRejected("multiplication with mismatched logical lengths", err)
	_, _, err = rescalePlan(ctx, aliceCiphertext.chunks[0].Level(), aliceCiphertext.chunks[0].Scale, math.NaN())
	assertRejected("non-finite rescale threshold", err)

	delete(keys.rot.Value[alice.sk.ID], 1)
	assertRejected("missing composite rotation key", requireRotationKeys(aliceCiphertext, keys, 3))

	fullContribution, err := generateEvalContribution(alice, true, []int{1}, true)
	if err != nil {
		t.Fatal(err)
	}
	fullKeys, err := combineEvalContributions([]*nativeEvalContribution{fullContribution})
	if err != nil {
		t.Fatal(err)
	}
	lowerLevel, err := levelCipher(aliceCiphertext, "drop", 1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = conjugateCipher(lowerLevel, fullKeys)
	assertRejected("lower-level conjugation", err)

	baseline := liveObjectCount()
	handle := putObject(kindCiphertext, aliceCiphertext)
	if _, err = getObject(handle, kindPublicKey); err == nil {
		t.Fatal("wrong handle kind accepted")
	}
	if liveObjectCount() != baseline+1 {
		t.Fatal("failed handle lookup changed the registry")
	}
	if err = releaseObject(handle); err != nil {
		t.Fatal(err)
	}
	if liveObjectCount() != baseline {
		t.Fatal("registry did not return to its baseline")
	}

	secretCopy := cloneSecretKey(alice.sk)
	partyHandle := putObject(kindParty, &nativeParty{ctx: ctx, sk: secretCopy, pk: alice.pk})
	if err = releaseObject(partyHandle); err != nil {
		t.Fatal(err)
	}
	if secretCopy.Value.Q.Coeffs[0][0] != 0 {
		t.Fatal("party release did not clear secret-key coefficients")
	}
}
