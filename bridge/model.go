// SPDX-License-Identifier: MIT
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/cmplx"
	"runtime"
	"sort"
	"sync"
	"unicode/utf8"

	"github.com/ldsec/lattigo/v2/ckks"
	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/rlwe"
	"mk-lattigo/mkckks"
	"mk-lattigo/mkrlwe"
)

const upstreamCommit = "13fed55fd28270fb4345dd532da24b323ebc5ce3"

const rangeSafetyBits = 3.0

type correctnessTracking struct {
	magnitudeBound float64
	errorBound     float64
	rangeExceeded  bool
}

type parameterLiteralDTO struct {
	LogN     int      `json:"log_n"`
	LogSlots int      `json:"log_slots"`
	Q        []uint64 `json:"q"`
	P        []uint64 `json:"p"`
	Scale    float64  `json:"scale"`
	Sigma    float64  `json:"sigma"`
}

type nativeContext struct {
	literal     parameterLiteralDTO
	params      mkckks.Parameters
	workers     int
	fingerprint string
	mu          sync.RWMutex
	partyIDs    map[string]struct{}
}

type nativeParty struct {
	ctx *nativeContext
	sk  *mkrlwe.SecretKey
	pk  *mkrlwe.PublicKey
}

type nativePublicKey struct {
	ctx *nativeContext
	pk  *mkrlwe.PublicKey
}

type nativeEvalContribution struct {
	ctx       *nativeContext
	id        string
	rlin      *mkrlwe.RelinearizationKey
	rotations map[int]*mkrlwe.RotationKey
	conj      *mkrlwe.ConjugationKey
}

type nativeEvalSet struct {
	ctx  *nativeContext
	rlin *mkrlwe.RelinearizationKeySet
	rot  *mkrlwe.RotationKeySet
	conj *mkrlwe.ConjugationKeySet
	ids  map[string]struct{}
}

type nativePlaintext struct {
	ctx       *nativeContext
	values    [][]complex128
	length    int
	isComplex bool
	tracking  correctnessTracking
}

type nativeCiphertext struct {
	ctx       *nativeContext
	chunks    []*mkckks.Ciphertext
	length    int
	isComplex bool
	artifact  [16]byte
	tracking  correctnessTracking
}

type nativeShare struct {
	ctx      *nativeContext
	partyID  string
	cipherID [16]byte
	length   int
	deltas   []*ring.Poly
}

func newContext(raw []byte, workers int) (*nativeContext, error) {
	if len(raw) == 0 || len(raw) > 1<<20 {
		return nil, fmt.Errorf("parameter literal must be between 1 byte and 1 MiB")
	}
	var dto parameterLiteralDTO
	if err := decodeParameterLiteral(raw, &dto); err != nil {
		return nil, fmt.Errorf("invalid parameter literal: %w", err)
	}
	if dto.LogN < 4 || dto.LogN > 20 || dto.LogSlots < 1 || dto.LogSlots >= dto.LogN {
		return nil, fmt.Errorf("invalid log_n/log_slots combination")
	}
	if len(dto.Q) == 0 || len(dto.Q) > 64 || len(dto.P) < 2 || len(dto.P) > 8 || len(dto.P)%2 != 0 || !isFinitePositive(dto.Scale) || !isFinitePositive(dto.Sigma) {
		return nil, fmt.Errorf("parameters require 1-64 Q moduli, 2-8 even-count P moduli, and finite positive scale/sigma")
	}
	literal := ckks.ParametersLiteral{LogN: dto.LogN, LogSlots: dto.LogSlots, Q: dto.Q, P: dto.P, Scale: dto.Scale, Sigma: dto.Sigma}
	params, err := ckks.NewParametersFromLiteral(literal)
	if err != nil {
		return nil, fmt.Errorf("Lattigo rejected parameters: %w", err)
	}
	if params.PCount() < 2 {
		return nil, fmt.Errorf("MKCKKS requires at least two P moduli")
	}
	if workers < 0 || workers > 1024 {
		return nil, fmt.Errorf("workers must be zero (automatic) or between 1 and 1024")
	}
	if workers == 0 {
		workers = runtime.NumCPU()
		if workers > 1024 {
			workers = 1024
		}
	}
	ctx := &nativeContext{
		literal: dto, params: mkckks.NewParameters(params), workers: workers,
		partyIDs: make(map[string]struct{}),
	}
	ctx.fingerprint = contextFingerprint(ctx)
	return ctx, nil
}

func decodeParameterLiteral(raw []byte, dto *parameterLiteralDTO) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return fmt.Errorf("parameter literal must be a JSON object")
	}
	allowed := map[string]struct{}{
		"log_n": {}, "log_slots": {}, "q": {}, "p": {}, "scale": {}, "sigma": {},
	}
	seen := make(map[string]json.RawMessage, len(allowed))
	for decoder.More() {
		keyToken, tokenErr := decoder.Token()
		if tokenErr != nil {
			return tokenErr
		}
		key, ok := keyToken.(string)
		if !ok {
			return fmt.Errorf("parameter field name is not a string")
		}
		if _, ok = allowed[key]; !ok {
			return fmt.Errorf("unknown parameter field %q", key)
		}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate parameter field %q", key)
		}
		var value json.RawMessage
		if err = decoder.Decode(&value); err != nil {
			return err
		}
		seen[key] = value
	}
	if _, err = decoder.Token(); err != nil {
		return err
	}
	if token, err = decoder.Token(); err != io.EOF {
		if err != nil {
			return err
		}
		return fmt.Errorf("trailing JSON value %v", token)
	}
	missing := make([]string, 0)
	for key := range allowed {
		if _, ok := seen[key]; !ok {
			missing = append(missing, key)
		}
	}
	if len(missing) != 0 {
		sort.Strings(missing)
		return fmt.Errorf("missing parameter fields %v", missing)
	}
	return json.Unmarshal(raw, dto)
}

func isFinitePositive(v float64) bool { return v > 0 && !math.IsInf(v, 0) && !math.IsNaN(v) }

func contextFingerprint(ctx *nativeContext) string {
	h := sha256.New()
	raw, _ := json.Marshal(ctx.literal)
	h.Write(raw)
	keys := make([]int, 0, len(ctx.params.CRS))
	for key := range ctx.params.CRS {
		keys = append(keys, key)
	}
	sort.Ints(keys)
	for _, key := range keys {
		_ = binary.Write(h, binary.BigEndian, int64(key))
		writeSwitchingKeyHash(h, ctx.params.CRS[key])
	}
	return hex.EncodeToString(h.Sum(nil))
}

type hashWriter interface{ Write([]byte) (int, error) }

func writeSwitchingKeyHash(w hashWriter, key *mkrlwe.SwitchingKey) {
	_ = binary.Write(w, binary.BigEndian, uint32(len(key.Value)))
	for i := range key.Value {
		for _, poly := range []*ring.Poly{key.Value[i].Q, key.Value[i].P} {
			data, _ := poly.MarshalBinary()
			_ = binary.Write(w, binary.BigEndian, uint64(len(data)))
			_, _ = w.Write(data)
		}
	}
}

func randomArtifactID() ([16]byte, error) {
	var id [16]byte
	_, err := rand.Read(id[:])
	return id, err
}

func validatePartyID(id string) error {
	if id == "" || id == "0" || len(id) > 128 || !utf8.ValidString(id) {
		return fmt.Errorf("party ID must be 1-128 bytes and cannot be reserved ID '0'")
	}
	for _, b := range []byte(id) {
		if b == 0 {
			return fmt.Errorf("party ID cannot contain NUL")
		}
	}
	return nil
}

func generateParty(ctx *nativeContext, id string) (*nativeParty, error) {
	if err := validatePartyID(id); err != nil {
		return nil, err
	}
	if err := reservePartyID(ctx, id); err != nil {
		return nil, err
	}
	keygen := mkckks.NewKeyGenerator(ctx.params)
	sk, pk := keygen.GenKeyPair(id)
	return &nativeParty{ctx: ctx, sk: sk, pk: pk}, nil
}

func reservePartyID(ctx *nativeContext, id string) error {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	if _, exists := ctx.partyIDs[id]; exists {
		return fmt.Errorf("duplicate party ID %q in this context", id)
	}
	ctx.partyIDs[id] = struct{}{}
	return nil
}

func zeroParty(p *nativeParty) {
	if p == nil || p.sk == nil {
		return
	}
	for _, poly := range []*ring.Poly{p.sk.Value.Q, p.sk.Value.P} {
		if poly == nil {
			continue
		}
		for i := range poly.Coeffs {
			for j := range poly.Coeffs[i] {
				poly.Coeffs[i][j] = 0
			}
		}
	}
}

func requireSameContext(a, b *nativeContext) error {
	if a == nil || b == nil || a.fingerprint != b.fingerprint {
		return fmt.Errorf("context/CRS fingerprint mismatch")
	}
	return nil
}

func splitValues(ctx *nativeContext, realValues, imagValues []float64, isComplex bool) [][]complex128 {
	slots := ctx.params.Slots()
	chunks := (len(realValues) + slots - 1) / slots
	values := make([][]complex128, chunks)
	for chunk := 0; chunk < chunks; chunk++ {
		start := chunk * slots
		end := start + slots
		if end > len(realValues) {
			end = len(realValues)
		}
		values[chunk] = make([]complex128, slots)
		for i := start; i < end; i++ {
			imag := 0.0
			if isComplex {
				imag = imagValues[i]
			}
			values[chunk][i-start] = complex(realValues[i], imag)
		}
	}
	return values
}

func boundedAdd(values ...float64) float64 {
	total := 0.0
	for _, value := range values {
		if value < 0 || math.IsNaN(value) || math.IsInf(value, 0) || total > math.MaxFloat64-value {
			return math.MaxFloat64
		}
		total += value
		if total != 0 {
			total = math.Nextafter(total, math.Inf(1))
		}
	}
	return total
}

func boundedMultiply(left, right float64) float64 {
	if left < 0 || right < 0 || math.IsNaN(left) || math.IsNaN(right) || math.IsInf(left, 0) || math.IsInf(right, 0) {
		return math.MaxFloat64
	}
	if left == 0 || right == 0 {
		return 0
	}
	if left > math.MaxFloat64/right {
		return math.MaxFloat64
	}
	return math.Nextafter(left*right, math.Inf(1))
}

func maximumValueMagnitude(values [][]complex128) float64 {
	maximum := 0.0
	for _, chunk := range values {
		for _, value := range chunk {
			if magnitude := cmplx.Abs(value); magnitude > maximum {
				maximum = magnitude
			}
		}
	}
	return maximum
}

func primitiveErrorBound(ctx *nativeContext, scale float64, slackBits float64) float64 {
	if !isFinitePositive(scale) {
		return math.MaxFloat64
	}
	value := math.Exp2(-math.Log2(scale) + float64(ctx.params.LogSlots()) + slackBits)
	if value < 0 || math.IsNaN(value) || math.IsInf(value, 0) {
		return math.MaxFloat64
	}
	return value
}

func encodingErrorBound(ctx *nativeContext, scale, magnitude float64) float64 {
	// The primitive CKKS formula covers normalized vectors. Lattigo v2.3.0's
	// complex128 FFT also accumulates ordinary floating-point roundoff that is
	// proportional to the encoded magnitude and transform depth. Four ulps per
	// FFT stage is deliberately conservative and is verified at the 2^20 input
	// boundary in the release matrix.
	fftRoundoff := boundedMultiply(
		magnitude,
		boundedMultiply(math.Nextafter(1, 2)-1, 4*float64(ctx.params.LogSlots())),
	)
	return boundedAdd(primitiveErrorBound(ctx, scale, 8), fftRoundoff)
}

func trackedRangeMargin(ctx *nativeContext, level int, scale float64, tracking correctnessTracking) float64 {
	logCapacity := -math.Log2(scale) - 1 - rangeSafetyBits
	for _, modulus := range ctx.params.Q()[:level+1] {
		logCapacity += math.Log2(float64(modulus))
	}
	total := boundedAdd(tracking.magnitudeBound, tracking.errorBound)
	// Zero has no meaningful logarithm. SmallestNonzeroFloat64 yields a
	// finite, deterministic positive margin suitable for JSON metadata.
	if total == 0 {
		total = math.SmallestNonzeroFloat64
	}
	return logCapacity - math.Log2(total)
}

func finalizeTracking(
	ctx *nativeContext,
	level int,
	scale float64,
	magnitude float64,
	errorBound float64,
	parentExceeded bool,
) correctnessTracking {
	tracking := correctnessTracking{
		magnitudeBound: boundedAdd(magnitude),
		errorBound:     boundedAdd(errorBound),
		rangeExceeded:  parentExceeded,
	}
	margin := trackedRangeMargin(ctx, level, scale, tracking)
	if math.IsNaN(margin) || math.IsInf(margin, 0) || margin < 0 {
		tracking.rangeExceeded = true
	}
	return tracking
}

func plaintextTracking(ctx *nativeContext, values [][]complex128) correctnessTracking {
	magnitude := maximumValueMagnitude(values)
	errorBound := 0.0
	if magnitude != 0 {
		errorBound = encodingErrorBound(ctx, ctx.params.Scale(), magnitude)
	}
	return finalizeTracking(ctx, ctx.params.MaxLevel(), ctx.params.Scale(), magnitude, errorBound, false)
}

func productTracking(
	ctx *nativeContext,
	level int,
	scale float64,
	left correctnessTracking,
	right correctnessTracking,
) correctnessTracking {
	magnitude := boundedMultiply(left.magnitudeBound, right.magnitudeBound)
	errorBound := boundedAdd(
		boundedMultiply(right.magnitudeBound, left.errorBound),
		boundedMultiply(left.magnitudeBound, right.errorBound),
		boundedMultiply(left.errorBound, right.errorBound),
		primitiveErrorBound(ctx, scale, 12),
	)
	return finalizeTracking(
		ctx, level, scale, magnitude, errorBound, left.rangeExceeded || right.rangeExceeded,
	)
}

func parallelFor(count, workers int, fn func(int) error) error {
	if count <= 1 || workers <= 1 {
		for i := 0; i < count; i++ {
			if err := fn(i); err != nil {
				return err
			}
		}
		return nil
	}
	if workers > count {
		workers = count
	}
	jobs := make(chan int)
	errs := make(chan error, count)
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				if err := fn(i); err != nil {
					errs <- err
				}
			}
		}()
	}
	for i := 0; i < count; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func encryptValues(ctx *nativeContext, pk *mkrlwe.PublicKey, values [][]complex128, length int, isComplex bool) (*nativeCiphertext, error) {
	result := &nativeCiphertext{ctx: ctx, chunks: make([]*mkckks.Ciphertext, len(values)), length: length, isComplex: isComplex}
	id, err := randomArtifactID()
	if err != nil {
		return nil, fmt.Errorf("generate artifact ID: %w", err)
	}
	result.artifact = id
	err = parallelFor(len(values), ctx.workers, func(i int) error {
		msg := mkckks.NewMessage(ctx.params)
		copy(msg.Value, values[i])
		result.chunks[i] = mkckks.NewEncryptor(ctx.params).EncryptMsgNew(msg, pk)
		return nil
	})
	if err == nil {
		magnitude := maximumValueMagnitude(values)
		result.tracking = finalizeTracking(
			ctx,
			result.chunks[0].Level(),
			result.chunks[0].Scale,
			magnitude,
			encodingErrorBound(ctx, result.chunks[0].Scale, magnitude),
			false,
		)
	}
	return result, err
}

func encodeValues(ctx *nativeContext, values [][]complex128, length int, isComplex bool) *nativePlaintext {
	return &nativePlaintext{
		ctx: ctx, values: values, length: length, isComplex: isComplex,
		tracking: plaintextTracking(ctx, values),
	}
}

func binaryCipher(op string, left, right *nativeCiphertext) (*nativeCiphertext, error) {
	if err := requireSameContext(left.ctx, right.ctx); err != nil {
		return nil, err
	}
	if left.length != right.length || len(left.chunks) != len(right.chunks) {
		return nil, statusFailure(statusInvalid, op, "ciphertext shape/length mismatch")
	}
	for i := range left.chunks {
		if !compatibleScales(left.chunks[i].Scale, right.chunks[i].Scale) {
			return nil, statusFailure(statusLevel, op, fmt.Sprintf("ciphertext scales are incompatible: %.17g and %.17g", left.chunks[i].Scale, right.chunks[i].Scale))
		}
	}
	out := &nativeCiphertext{ctx: left.ctx, chunks: make([]*mkckks.Ciphertext, len(left.chunks)), length: left.length, isComplex: left.isComplex || right.isComplex}
	id, err := randomArtifactID()
	if err != nil {
		return nil, err
	}
	out.artifact = id
	err = parallelFor(len(out.chunks), left.ctx.workers, func(i int) error {
		eval := mkckks.NewEvaluator(left.ctx.params)
		switch op {
		case "add":
			out.chunks[i] = eval.AddNew(left.chunks[i], right.chunks[i])
		case "sub":
			out.chunks[i] = eval.SubNew(left.chunks[i], right.chunks[i])
		default:
			return fmt.Errorf("unknown binary operation %q", op)
		}
		return nil
	})
	if err == nil {
		out.tracking = finalizeTracking(
			left.ctx,
			out.chunks[0].Level(),
			out.chunks[0].Scale,
			boundedAdd(left.tracking.magnitudeBound, right.tracking.magnitudeBound),
			boundedAdd(
				left.tracking.errorBound,
				right.tracking.errorBound,
				primitiveErrorBound(left.ctx, out.chunks[0].Scale, 8),
			),
			left.tracking.rangeExceeded || right.tracking.rangeExceeded,
		)
	}
	return out, err
}

func compatibleScales(left, right float64) bool {
	if !isFinitePositive(left) || !isFinitePositive(right) {
		return false
	}
	if left == right {
		return true
	}
	ratio := math.Max(left, right) / math.Min(left, right)
	// Rescaling by adjacent ~52/54-bit primes leaves scales that differ by a
	// few parts per billion. Upstream intentionally treats those as equal.
	if ratio <= 1.000001 {
		return true
	}
	nearest := math.Round(ratio)
	if nearest < 1 || nearest > 1<<53 {
		return false
	}
	return math.Abs(ratio-nearest) <= math.Max(4*math.Nextafter(ratio, math.Inf(1))-4*ratio, 1e-12*ratio)
}

func encodeForCipher(
	ctx *nativeContext, values []complex128, level int, scale float64,
) (*ckks.Plaintext, error) {
	params, err := ckks.NewParameters(ctx.params.Parameters.Parameters, ctx.params.LogSlots(), scale)
	if err != nil {
		return nil, fmt.Errorf("construct plaintext parameters: %w", err)
	}
	plaintext := ckks.NewPlaintext(params, level, scale)
	ckks.NewEncoder(params).Encode(plaintext, values, ctx.params.LogSlots())
	return plaintext, nil
}

func addPlaintextCipher(
	input *nativeCiphertext, plaintext *nativePlaintext, subtract bool,
) (*nativeCiphertext, error) {
	if err := requireSameContext(input.ctx, plaintext.ctx); err != nil {
		return nil, err
	}
	if input.length != plaintext.length || len(input.chunks) != len(plaintext.values) {
		return nil, fmt.Errorf("ciphertext/plaintext shape mismatch")
	}
	out := &nativeCiphertext{
		ctx: input.ctx, chunks: make([]*mkckks.Ciphertext, len(input.chunks)),
		length: input.length, isComplex: input.isComplex || plaintext.isComplex,
	}
	id, err := randomArtifactID()
	if err != nil {
		return nil, err
	}
	out.artifact = id
	err = parallelFor(len(out.chunks), input.ctx.workers, func(i int) error {
		out.chunks[i] = input.chunks[i].CopyNew()
		encoded, encodeErr := encodeForCipher(
			input.ctx, plaintext.values[i], input.chunks[i].Level(), input.chunks[i].Scale,
		)
		if encodeErr != nil {
			return encodeErr
		}
		if subtract {
			input.ctx.params.RingQ().SubLvl(
				input.chunks[i].Level(), out.chunks[i].Value["0"], encoded.Value,
				out.chunks[i].Value["0"],
			)
		} else {
			input.ctx.params.RingQ().AddLvl(
				input.chunks[i].Level(), out.chunks[i].Value["0"], encoded.Value,
				out.chunks[i].Value["0"],
			)
		}
		return nil
	})
	if err == nil {
		if plaintext.tracking.magnitudeBound == 0 && plaintext.tracking.errorBound == 0 {
			out.tracking = input.tracking
		} else {
			encodedError := encodingErrorBound(
				input.ctx, out.chunks[0].Scale, plaintext.tracking.magnitudeBound,
			)
			out.tracking = finalizeTracking(
				input.ctx,
				out.chunks[0].Level(),
				out.chunks[0].Scale,
				boundedAdd(input.tracking.magnitudeBound, plaintext.tracking.magnitudeBound),
				boundedAdd(
					input.tracking.errorBound,
					encodedError,
					primitiveErrorBound(input.ctx, out.chunks[0].Scale, 8),
				),
				input.tracking.rangeExceeded || plaintext.tracking.rangeExceeded,
			)
		}
	}
	return out, err
}

func addScalarCipher(input *nativeCiphertext, scalar complex128, subtract bool) (*nativeCiphertext, error) {
	values := make([][]complex128, len(input.chunks))
	remaining := input.length
	for i := range values {
		values[i] = make([]complex128, input.ctx.params.Slots())
		used := remaining
		if used > len(values[i]) {
			used = len(values[i])
		}
		for slot := 0; slot < used; slot++ {
			values[i][slot] = scalar
		}
		remaining -= used
	}
	plaintext := &nativePlaintext{
		ctx: input.ctx, values: values, length: input.length, isComplex: imag(scalar) != 0,
	}
	plaintext.tracking = plaintextTracking(input.ctx, values)
	return addPlaintextCipher(input, plaintext, subtract)
}

func scalarCipher(input *nativeCiphertext, scalar complex128) (*nativeCiphertext, error) {
	if math.IsNaN(real(scalar)) || math.IsInf(real(scalar), 0) || math.IsNaN(imag(scalar)) || math.IsInf(imag(scalar), 0) {
		return nil, fmt.Errorf("scalar must be finite")
	}
	out := &nativeCiphertext{ctx: input.ctx, chunks: make([]*mkckks.Ciphertext, len(input.chunks)), length: input.length, isComplex: input.isComplex || imag(scalar) != 0}
	id, err := randomArtifactID()
	if err != nil {
		return nil, err
	}
	out.artifact = id
	err = parallelFor(len(out.chunks), input.ctx.workers, func(i int) error {
		evaluator := mkckks.NewEvaluator(input.ctx.params)
		if imag(scalar) != 0 || math.Trunc(real(scalar)) != real(scalar) {
			// Upstream's complex fractional MultByConst path is not numerically
			// reliable in this pinned revision. Encoding a constant plaintext and
			// invoking the upstream plaintext product preserves its CKKS semantics
			// without changing upstream code.
			message := mkckks.NewMessage(input.ctx.params)
			for slot := range message.Value {
				message.Value[slot] = scalar
			}
			plaintext := mkckks.NewEncryptor(input.ctx.params).EncodeMsgNew(message)
			out.chunks[i] = evaluator.MulPtxtNew(input.chunks[i], plaintext)
		} else {
			out.chunks[i] = input.chunks[i].CopyNew()
			evaluator.MultByConst(out.chunks[i], real(scalar), out.chunks[i])
		}
		return nil
	})
	if err == nil {
		magnitude := cmplx.Abs(scalar)
		switch {
		case scalar == 1 || scalar == -1:
			out.tracking = input.tracking
		case scalar == 0:
			out.tracking = finalizeTracking(
				input.ctx, out.chunks[0].Level(), out.chunks[0].Scale,
				0, 0, input.tracking.rangeExceeded,
			)
		case imag(scalar) == 0 && math.Trunc(real(scalar)) == real(scalar):
			out.tracking = finalizeTracking(
				input.ctx, out.chunks[0].Level(), out.chunks[0].Scale,
				boundedMultiply(input.tracking.magnitudeBound, magnitude),
				boundedAdd(
					boundedMultiply(input.tracking.errorBound, magnitude),
					primitiveErrorBound(input.ctx, out.chunks[0].Scale, 8),
				),
				input.tracking.rangeExceeded,
			)
		default:
			constant := finalizeTracking(
				input.ctx, input.ctx.params.MaxLevel(), input.ctx.params.Scale(),
				magnitude, encodingErrorBound(input.ctx, input.ctx.params.Scale(), magnitude), false,
			)
			out.tracking = productTracking(
				input.ctx, out.chunks[0].Level(), out.chunks[0].Scale, input.tracking, constant,
			)
		}
	}
	return out, err
}

func plaintextCipher(input *nativeCiphertext, plaintext *nativePlaintext) (*nativeCiphertext, error) {
	if err := requireSameContext(input.ctx, plaintext.ctx); err != nil {
		return nil, err
	}
	if input.length != plaintext.length || len(input.chunks) != len(plaintext.values) {
		return nil, fmt.Errorf("ciphertext/plaintext shape mismatch")
	}
	for _, chunk := range input.chunks {
		if chunk.Level() == 0 {
			return nil, statusFailure(statusLevel, "multiply plaintext", "ciphertext/plaintext multiplication requires a positive level")
		}
	}
	out := &nativeCiphertext{ctx: input.ctx, chunks: make([]*mkckks.Ciphertext, len(input.chunks)), length: input.length, isComplex: input.isComplex || plaintext.isComplex}
	id, err := randomArtifactID()
	if err != nil {
		return nil, err
	}
	out.artifact = id
	err = parallelFor(len(out.chunks), input.ctx.workers, func(i int) error {
		msg := mkckks.NewMessage(input.ctx.params)
		copy(msg.Value, plaintext.values[i])
		encoder := mkckks.NewEncryptor(input.ctx.params)
		pt := encoder.EncodeMsgNew(msg)
		out.chunks[i] = mkckks.NewEvaluator(input.ctx.params).MulPtxtNew(input.chunks[i], pt)
		return nil
	})
	if err == nil {
		out.tracking = productTracking(
			input.ctx, out.chunks[0].Level(), out.chunks[0].Scale,
			input.tracking, plaintext.tracking,
		)
	}
	return out, err
}

func generateEvalContribution(party *nativeParty, relinearization bool, rotations []int, conjugation bool) (*nativeEvalContribution, error) {
	keygen := mkckks.NewKeyGenerator(party.ctx.params)
	result := &nativeEvalContribution{ctx: party.ctx, id: party.sk.ID, rotations: make(map[int]*mkrlwe.RotationKey)}
	if relinearization {
		r := keygen.GenSecretKey(party.sk.ID)
		result.rlin = keygen.GenRelinearizationKey(party.sk, r)
	}
	needed := make(map[int]struct{})
	for _, rotation := range rotations {
		normalized := rotation
		for normalized < 0 {
			normalized += party.ctx.params.Slots()
		}
		normalized %= party.ctx.params.Slots()
		for bit := 1; normalized > 0; bit <<= 1 {
			if normalized&1 == 1 {
				needed[bit] = struct{}{}
			}
			normalized >>= 1
		}
	}
	keys := make([]int, 0, len(needed))
	for rotation := range needed {
		keys = append(keys, rotation)
	}
	sort.Ints(keys)
	for _, rotation := range keys {
		result.rotations[rotation] = keygen.GenRotationKey(rotation, party.sk)
	}
	if conjugation {
		result.conj = keygen.GenConjugationKey(party.sk)
	}
	return result, nil
}

func combineEvalContributions(contributions []*nativeEvalContribution) (*nativeEvalSet, error) {
	if len(contributions) == 0 {
		return nil, fmt.Errorf("at least one evaluation-key contribution is required")
	}
	ctx := contributions[0].ctx
	result := &nativeEvalSet{
		ctx:  ctx,
		rlin: mkrlwe.NewRelinearizationKeyKeySet(ctx.params.Parameters),
		rot:  mkrlwe.NewRotationKeySet(),
		conj: mkrlwe.NewConjugationKeySet(),
		ids:  make(map[string]struct{}),
	}
	for _, contribution := range contributions {
		if err := requireSameContext(ctx, contribution.ctx); err != nil {
			return nil, err
		}
		if _, exists := result.ids[contribution.id]; exists {
			return nil, fmt.Errorf("duplicate evaluation-key contribution for %q", contribution.id)
		}
		result.ids[contribution.id] = struct{}{}
		if contribution.rlin != nil {
			result.rlin.AddRelinearizationKey(contribution.rlin)
		}
		for _, key := range contribution.rotations {
			result.rot.AddRotationKey(key)
		}
		if contribution.conj != nil {
			result.conj.AddConjugationKey(contribution.conj)
		}
	}
	return result, nil
}

func requireEvaluationCoverage(ciphertext *nativeCiphertext, keys *nativeEvalSet) error {
	if err := requireSameContext(ciphertext.ctx, keys.ctx); err != nil {
		return err
	}
	for id := range ciphertext.chunks[0].IDSet().Value {
		if _, ok := keys.ids[id]; !ok {
			return fmt.Errorf("evaluation keys missing participant %q", id)
		}
	}
	return nil
}

func requireRelinearizationKeys(ciphertext *nativeCiphertext, keys *nativeEvalSet) error {
	if err := requireEvaluationCoverage(ciphertext, keys); err != nil {
		return err
	}
	for id := range ciphertext.chunks[0].IDSet().Value {
		if _, ok := keys.rlin.Value[id]; !ok {
			return fmt.Errorf("relinearization key missing participant %q", id)
		}
	}
	return nil
}

func requiredRotationBits(slots, rotation int) []uint {
	normalized := rotation
	for normalized < 0 {
		normalized += slots
	}
	normalized %= slots
	bits := make([]uint, 0)
	for bit := 1; normalized > 0; bit <<= 1 {
		if normalized&1 == 1 {
			bits = append(bits, uint(bit))
		}
		normalized >>= 1
	}
	return bits
}

func requireRotationKeys(ciphertext *nativeCiphertext, keys *nativeEvalSet, rotation int) error {
	if err := requireEvaluationCoverage(ciphertext, keys); err != nil {
		return err
	}
	bits := requiredRotationBits(ciphertext.ctx.params.Slots(), rotation)
	for id := range ciphertext.chunks[0].IDSet().Value {
		partyKeys, ok := keys.rot.Value[id]
		if !ok {
			return fmt.Errorf("rotation keys missing participant %q", id)
		}
		for _, bit := range bits {
			if _, ok := partyKeys[bit]; !ok {
				return fmt.Errorf("rotation key %d missing participant %q", bit, id)
			}
		}
	}
	return nil
}

func requireConjugationKeys(ciphertext *nativeCiphertext, keys *nativeEvalSet) error {
	if err := requireEvaluationCoverage(ciphertext, keys); err != nil {
		return err
	}
	for id := range ciphertext.chunks[0].IDSet().Value {
		if _, ok := keys.conj.Value[id]; !ok {
			return fmt.Errorf("conjugation key missing participant %q", id)
		}
	}
	return nil
}

func multiplyCipher(left, right *nativeCiphertext, keys *nativeEvalSet, hoisted bool) (*nativeCiphertext, error) {
	if err := requireSameContext(left.ctx, right.ctx); err != nil {
		return nil, err
	}
	if left.length != right.length || len(left.chunks) != len(right.chunks) {
		return nil, fmt.Errorf("ciphertext shape/length mismatch")
	}
	for i := range left.chunks {
		if left.chunks[i].Level() == 0 || right.chunks[i].Level() == 0 {
			return nil, statusFailure(statusLevel, "multiply", "ciphertext multiplication requires a positive level")
		}
	}
	if err := requireRelinearizationKeys(left, keys); err != nil {
		return nil, err
	}
	if err := requireRelinearizationKeys(right, keys); err != nil {
		return nil, err
	}
	out := &nativeCiphertext{ctx: left.ctx, chunks: make([]*mkckks.Ciphertext, len(left.chunks)), length: left.length, isComplex: left.isComplex || right.isComplex}
	id, err := randomArtifactID()
	if err != nil {
		return nil, err
	}
	out.artifact = id
	err = parallelFor(len(out.chunks), left.ctx.workers, func(i int) error {
		eval := mkckks.NewEvaluator(left.ctx.params)
		// Upstream MulRelinNew stores decomposition scratch in the shared key
		// set. Use operation-local hoisted forms for both public modes so a key
		// set remains immutable and safe across chunks and concurrent callers.
		a := eval.HoistedForm(left.chunks[i])
		b := a
		if left.chunks[i] != right.chunks[i] {
			b = eval.HoistedForm(right.chunks[i])
		}
		out.chunks[i] = eval.MulRelinHoistedNew(left.chunks[i], right.chunks[i], a, b, keys.rlin)
		return nil
	})
	if err == nil {
		out.tracking = productTracking(
			left.ctx, out.chunks[0].Level(), out.chunks[0].Scale,
			left.tracking, right.tracking,
		)
	}
	_ = hoisted // Retained for ABI/API compatibility; both paths are now race-free.
	return out, err
}

func rescalePlan(ctx *nativeContext, level int, scale, minimumScale float64) (int, float64, error) {
	if !isFinitePositive(minimumScale) {
		return 0, 0, fmt.Errorf("minimum scale must be finite and positive")
	}
	if level <= 0 || level > ctx.params.MaxLevel() || !isFinitePositive(scale) {
		return 0, 0, fmt.Errorf("cannot rescale a ciphertext at level %d", level)
	}
	resultScale := scale
	consumed := 0
	for consumed <= level && resultScale/float64(ctx.params.Q()[level-consumed]) >= minimumScale/2 {
		resultScale /= float64(ctx.params.Q()[level-consumed])
		consumed++
	}
	if consumed > level {
		return 0, 0, fmt.Errorf("rescale threshold would consume all remaining levels")
	}
	minimumSupportedScale := ctx.params.Scale() / 2
	if resultScale < minimumSupportedScale {
		return 0, 0, fmt.Errorf(
			"rescale would reduce scale %.17g below supported minimum %.17g",
			resultScale,
			minimumSupportedScale,
		)
	}
	return consumed, resultScale, nil
}

func levelCipher(input *nativeCiphertext, operation string, value float64) (*nativeCiphertext, error) {
	out := &nativeCiphertext{ctx: input.ctx, chunks: make([]*mkckks.Ciphertext, len(input.chunks)), length: input.length, isComplex: input.isComplex}
	id, err := randomArtifactID()
	if err != nil {
		return nil, err
	}
	out.artifact = id
	err = parallelFor(len(out.chunks), input.ctx.workers, func(i int) error {
		eval := mkckks.NewEvaluator(input.ctx.params)
		switch operation {
		case "drop":
			levels := int(value)
			if levels < 0 || levels > input.chunks[i].Level() {
				return fmt.Errorf("cannot drop %d levels from level %d", levels, input.chunks[i].Level())
			}
			out.chunks[i] = eval.DropLevelNew(input.chunks[i], levels)
		case "rescale":
			// Simulate the exact upstream boundary before entering it. The
			// planner also rejects technically positive but unusably low scales.
			if _, _, planErr := rescalePlan(
				input.ctx, input.chunks[i].Level(), input.chunks[i].Scale, value,
			); planErr != nil {
				return planErr
			}
			var rescaleErr error
			candidate, rescaleErr := eval.RescaleNew(input.chunks[i], value)
			if rescaleErr == nil && candidate.Level() == input.chunks[i].Level() {
				// In this pinned revision, upstream RescaleNew leaves its newly
				// allocated output at zero when no modulus is consumed. Preserve
				// immutable no-op semantics with an explicit copy.
				out.chunks[i] = input.chunks[i].CopyNew()
			} else {
				out.chunks[i] = candidate
			}
			return rescaleErr
		default:
			return fmt.Errorf("unknown level operation")
		}
		return nil
	})
	if err == nil {
		noOp := out.chunks[0].Level() == input.chunks[0].Level() &&
			out.chunks[0].Scale == input.chunks[0].Scale
		if noOp {
			out.tracking = input.tracking
		} else {
			out.tracking = finalizeTracking(
				input.ctx, out.chunks[0].Level(), out.chunks[0].Scale,
				input.tracking.magnitudeBound,
				boundedAdd(
					input.tracking.errorBound,
					primitiveErrorBound(input.ctx, out.chunks[0].Scale, 8),
				),
				input.tracking.rangeExceeded,
			)
		}
	}
	return out, err
}

func rotateCipher(input *nativeCiphertext, keys *nativeEvalSet, rotation int, hoisted bool) (*nativeCiphertext, error) {
	normalized := rotation % input.ctx.params.Slots()
	if normalized < 0 {
		normalized += input.ctx.params.Slots()
	}
	if normalized == 0 {
		out := &nativeCiphertext{ctx: input.ctx, chunks: make([]*mkckks.Ciphertext, len(input.chunks)), length: input.length, isComplex: input.isComplex}
		id, err := randomArtifactID()
		if err != nil {
			return nil, err
		}
		out.artifact = id
		for i := range input.chunks {
			out.chunks[i] = input.chunks[i].CopyNew()
		}
		out.tracking = input.tracking
		return out, nil
	}
	if err := requireRotationKeys(input, keys, rotation); err != nil {
		return nil, err
	}
	out := &nativeCiphertext{ctx: input.ctx, chunks: make([]*mkckks.Ciphertext, len(input.chunks)), length: input.length, isComplex: input.isComplex}
	id, err := randomArtifactID()
	if err != nil {
		return nil, err
	}
	out.artifact = id
	err = parallelFor(len(out.chunks), input.ctx.workers, func(i int) error {
		eval := mkckks.NewEvaluator(input.ctx.params)
		if hoisted && normalized&(normalized-1) == 0 {
			h := eval.HoistedForm(input.chunks[i])
			out.chunks[i] = eval.RotateHoistedNew(input.chunks[i], normalized, h, keys.rot)
		} else {
			out.chunks[i] = eval.RotateNew(input.chunks[i], rotation, keys.rot)
		}
		return nil
	})
	if err == nil {
		out.tracking = finalizeTracking(
			input.ctx, out.chunks[0].Level(), out.chunks[0].Scale,
			input.tracking.magnitudeBound,
			boundedAdd(
				input.tracking.errorBound,
				primitiveErrorBound(input.ctx, out.chunks[0].Scale, 11),
			),
			input.tracking.rangeExceeded,
		)
	}
	return out, err
}

func conjugateCipher(input *nativeCiphertext, keys *nativeEvalSet) (*nativeCiphertext, error) {
	for _, chunk := range input.chunks {
		if chunk.Level() != input.ctx.params.MaxLevel() {
			// The pinned upstream conjugation path calls ring.Permute, which
			// unconditionally indexes every Q modulus even when the ciphertext
			// has been rescaled or level-dropped. Reject the unsupported state
			// before protected upstream can panic.
			return nil, statusFailure(
				statusLevel,
				"conjugate",
				"the pinned upstream implementation supports conjugation only at the maximum level",
			)
		}
	}
	if err := requireConjugationKeys(input, keys); err != nil {
		return nil, err
	}
	out := &nativeCiphertext{ctx: input.ctx, chunks: make([]*mkckks.Ciphertext, len(input.chunks)), length: input.length, isComplex: input.isComplex}
	id, err := randomArtifactID()
	if err != nil {
		return nil, err
	}
	out.artifact = id
	err = parallelFor(len(out.chunks), input.ctx.workers, func(i int) error {
		out.chunks[i] = mkckks.NewEvaluator(input.ctx.params).ConjugateNew(input.chunks[i], keys.conj)
		return nil
	})
	if err == nil {
		out.tracking = finalizeTracking(
			input.ctx, out.chunks[0].Level(), out.chunks[0].Scale,
			input.tracking.magnitudeBound,
			boundedAdd(
				input.tracking.errorBound,
				primitiveErrorBound(input.ctx, out.chunks[0].Scale, 11),
			),
			input.tracking.rangeExceeded,
		)
	}
	return out, err
}

func partialDecrypt(party *nativeParty, ciphertext *nativeCiphertext) (*nativeShare, error) {
	if err := requireSameContext(party.ctx, ciphertext.ctx); err != nil {
		return nil, err
	}
	if !ciphertext.chunks[0].IDSet().Has(party.sk.ID) {
		return nil, fmt.Errorf("ciphertext does not contain participant %q", party.sk.ID)
	}
	share := &nativeShare{ctx: party.ctx, partyID: party.sk.ID, cipherID: ciphertext.artifact, length: ciphertext.length, deltas: make([]*ring.Poly, len(ciphertext.chunks))}
	err := parallelFor(len(ciphertext.chunks), party.ctx.workers, func(i int) error {
		original := ciphertext.chunks[i]
		partial := original.CopyNew()
		mkckks.NewDecryptor(party.ctx.params).PartialDecrypt(partial, party.sk)
		delta := original.Value["0"].CopyNew()
		party.ctx.params.RingQ().SubLvl(original.Level(), partial.Value["0"], original.Value["0"], delta)
		share.deltas[i] = delta
		return nil
	})
	return share, err
}

func collectiveDecrypt(ciphertext *nativeCiphertext, shares []*nativeShare) ([]complex128, error) {
	participants := ciphertext.chunks[0].IDSet()
	if len(shares) != participants.Size() {
		return nil, fmt.Errorf("need %d unique shares, received %d", participants.Size(), len(shares))
	}
	seen := make(map[string]struct{})
	for _, share := range shares {
		if err := requireSameContext(ciphertext.ctx, share.ctx); err != nil {
			return nil, err
		}
		if share.cipherID != ciphertext.artifact || share.length != ciphertext.length || len(share.deltas) != len(ciphertext.chunks) {
			return nil, fmt.Errorf("share is bound to a different ciphertext")
		}
		if !participants.Has(share.partyID) {
			return nil, fmt.Errorf("unexpected share from %q", share.partyID)
		}
		if _, ok := seen[share.partyID]; ok {
			return nil, fmt.Errorf("duplicate share from %q", share.partyID)
		}
		seen[share.partyID] = struct{}{}
	}
	values := make([]complex128, 0, len(ciphertext.chunks)*ciphertext.ctx.params.Slots())
	for chunkIndex, encrypted := range ciphertext.chunks {
		combined := &mkckks.Ciphertext{Ciphertext: &mkrlwe.Ciphertext{Value: map[string]*ring.Poly{"0": encrypted.Value["0"].CopyNew()}}, Scale: encrypted.Scale}
		for _, share := range shares {
			if len(share.deltas[chunkIndex].Coeffs) != encrypted.Level()+1 {
				return nil, fmt.Errorf("decryption share level does not match ciphertext")
			}
			ciphertext.ctx.params.RingQ().AddLvl(encrypted.Level(), combined.Value["0"], share.deltas[chunkIndex], combined.Value["0"])
		}
		message := mkckks.NewDecryptor(ciphertext.ctx.params).Decrypt(combined, mkrlwe.NewSecretKeySet())
		values = append(values, message.Value...)
	}
	return values[:ciphertext.length], nil
}

func participantIDs(ciphertext *nativeCiphertext) []string {
	ids := make([]string, 0, ciphertext.chunks[0].IDSet().Size())
	for id := range ciphertext.chunks[0].IDSet().Value {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func serializePoly(poly *ring.Poly) ([]byte, error) { return poly.MarshalBinary() }

func validateSerializedPoly(data []byte) error {
	const headerSize = uint64(4)
	if len(data) < int(headerSize) {
		return fmt.Errorf("invalid polynomial encoding: truncated header")
	}
	logN := data[0]
	if logN < 4 || logN > 20 {
		return fmt.Errorf("invalid polynomial encoding: log_n %d is outside [4, 20]", logN)
	}
	modulusCount := uint64(data[1])
	if modulusCount == 0 {
		return fmt.Errorf("invalid polynomial encoding: modulus count is zero")
	}
	if data[2] > 1 || data[3] > 1 {
		return fmt.Errorf("invalid polynomial encoding: Boolean flags must be 0 or 1")
	}
	coefficientCount := (uint64(1) << logN) * modulusCount
	expectedLength := headerSize + coefficientCount*8
	if expectedLength > maxArtifactSize {
		return fmt.Errorf("invalid polynomial encoding: declared size exceeds artifact limit")
	}
	if uint64(len(data)) != expectedLength {
		return fmt.Errorf(
			"invalid polynomial encoding: length %d does not match declared length %d",
			len(data),
			expectedLength,
		)
	}
	return nil
}

func deserializePoly(data []byte) (*ring.Poly, error) {
	// Lattigo v2.3.0's decoder indexes the four-byte header before validating
	// its length. Validate the complete allocation shape here so malformed
	// artifacts cannot panic or induce an oversized allocation upstream.
	if err := validateSerializedPoly(data); err != nil {
		return nil, err
	}
	poly := new(ring.Poly)
	if err := poly.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	return poly, nil
}

func encodeLengthPrefixed(buffer *bytes.Buffer, data []byte) {
	_ = binary.Write(buffer, binary.BigEndian, uint64(len(data)))
	buffer.Write(data)
}

func decodeLengthPrefixed(reader *bytes.Reader, maximum uint64) ([]byte, error) {
	var size uint64
	if err := binary.Read(reader, binary.BigEndian, &size); err != nil {
		return nil, err
	}
	if size > maximum || size > uint64(reader.Len()) {
		return nil, fmt.Errorf("invalid serialized field length %d", size)
	}
	data := make([]byte, size)
	_, err := reader.Read(data)
	return data, err
}

func clonePublicKey(pk *mkrlwe.PublicKey) *mkrlwe.PublicKey { return pk.CopyNew() }

func cloneSecretKey(sk *mkrlwe.SecretKey) *mkrlwe.SecretKey { return sk.CopyNew() }

var _ = rlwe.DefaultSigma
