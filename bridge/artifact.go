// SPDX-License-Identifier: MIT
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"

	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/rlwe"
	"mk-lattigo/mkckks"
	"mk-lattigo/mkrlwe"
)

var artifactMagic = [8]byte{'M', 'K', 'C', 'K', 'K', 'S', 'G', '2'}

const (
	artifactMajor   = uint16(1)
	artifactMinor   = uint16(0)
	maxArtifactSize = uint64(1 << 30)
)

type binaryWriter struct {
	bytes.Buffer
	err error
}

func (w *binaryWriter) u8(value uint8)    { w.write(value) }
func (w *binaryWriter) u16(value uint16)  { w.write(value) }
func (w *binaryWriter) u32(value uint32)  { w.write(value) }
func (w *binaryWriter) u64(value uint64)  { w.write(value) }
func (w *binaryWriter) i64(value int64)   { w.write(value) }
func (w *binaryWriter) f64(value float64) { w.u64(math.Float64bits(value)) }
func (w *binaryWriter) write(value interface{}) {
	if w.err == nil {
		w.err = binary.Write(&w.Buffer, binary.BigEndian, value)
	}
}
func (w *binaryWriter) raw(data []byte) {
	if w.err == nil {
		_, w.err = w.Write(data)
	}
}
func (w *binaryWriter) bytes(data []byte) {
	w.u64(uint64(len(data)))
	w.raw(data)
}
func (w *binaryWriter) string(value string) { w.bytes([]byte(value)) }

type binaryReader struct {
	*bytes.Reader
	err error
}

func newBinaryReader(data []byte) *binaryReader { return &binaryReader{Reader: bytes.NewReader(data)} }
func (r *binaryReader) read(value interface{}) {
	if r.err == nil {
		r.err = binary.Read(r.Reader, binary.BigEndian, value)
	}
}
func (r *binaryReader) u8() uint8    { var v uint8; r.read(&v); return v }
func (r *binaryReader) u16() uint16  { var v uint16; r.read(&v); return v }
func (r *binaryReader) u32() uint32  { var v uint32; r.read(&v); return v }
func (r *binaryReader) u64() uint64  { var v uint64; r.read(&v); return v }
func (r *binaryReader) i64() int64   { var v int64; r.read(&v); return v }
func (r *binaryReader) f64() float64 { return math.Float64frombits(r.u64()) }
func (r *binaryReader) bytes(max uint64) []byte {
	size := r.u64()
	if r.err != nil {
		return nil
	}
	if size > max || size > uint64(r.Len()) {
		r.err = fmt.Errorf("invalid artifact field length %d", size)
		return nil
	}
	value := make([]byte, size)
	_, r.err = io.ReadFull(r.Reader, value)
	return value
}
func (r *binaryReader) string(max uint64) string { return string(r.bytes(max)) }
func (r *binaryReader) done() error {
	if r.err != nil {
		return r.err
	}
	if r.Len() != 0 {
		return fmt.Errorf("artifact contains %d trailing bytes", r.Len())
	}
	return nil
}

func wrapArtifact(kind objectKind, fingerprint string, payload []byte) ([]byte, error) {
	if uint64(len(payload)) > maxArtifactSize {
		return nil, fmt.Errorf("artifact payload is too large")
	}
	w := new(binaryWriter)
	w.raw(artifactMagic[:])
	w.u16(artifactMajor)
	w.u16(artifactMinor)
	w.u8(uint8(kind))
	w.u32(abiVersion)
	w.string(upstreamCommit)
	w.string(fingerprint)
	w.bytes(payload)
	if w.err != nil {
		return nil, w.err
	}
	digest := sha256.Sum256(w.Bytes())
	w.raw(digest[:])
	return w.Bytes(), w.err
}

func unwrapArtifact(data []byte) (objectKind, string, []byte, error) {
	if len(data) < len(artifactMagic)+2+2+1+32 || uint64(len(data)) > maxArtifactSize {
		return 0, "", nil, fmt.Errorf("invalid artifact size")
	}
	body := data[:len(data)-sha256.Size]
	expected := sha256.Sum256(body)
	if !bytes.Equal(expected[:], data[len(data)-sha256.Size:]) {
		return 0, "", nil, fmt.Errorf("artifact checksum mismatch (checksum is corruption detection, not authentication)")
	}
	r := newBinaryReader(body)
	magic := make([]byte, len(artifactMagic))
	_, r.err = io.ReadFull(r.Reader, magic)
	if !bytes.Equal(magic, artifactMagic[:]) {
		return 0, "", nil, fmt.Errorf("invalid artifact magic")
	}
	major, minor := r.u16(), r.u16()
	if major != artifactMajor || minor > artifactMinor {
		return 0, "", nil, fmt.Errorf("unsupported artifact version %d.%d", major, minor)
	}
	kind := objectKind(r.u8())
	if artifactABI := r.u32(); artifactABI != abiVersion {
		return 0, "", nil, fmt.Errorf("artifact ABI version mismatch: %d", artifactABI)
	}
	if commit := r.string(128); commit != upstreamCommit {
		return 0, "", nil, fmt.Errorf("artifact upstream commit mismatch")
	}
	fingerprint := r.string(128)
	payload := r.bytes(maxArtifactSize)
	if err := r.done(); err != nil {
		return 0, "", nil, err
	}
	return kind, fingerprint, payload, nil
}

func writePoly(w *binaryWriter, poly *ring.Poly) {
	data, err := poly.MarshalBinary()
	if err != nil {
		w.err = err
		return
	}
	w.bytes(data)
}

func readPoly(r *binaryReader) *ring.Poly {
	data := r.bytes(maxArtifactSize)
	if r.err != nil {
		return nil
	}
	poly, err := deserializePoly(data)
	if err != nil {
		r.err = err
	}
	return poly
}

func writeCorrectnessTracking(w *binaryWriter, tracking correctnessTracking) {
	w.f64(tracking.magnitudeBound)
	w.f64(tracking.errorBound)
	if tracking.rangeExceeded {
		w.u8(1)
	} else {
		w.u8(0)
	}
}

func readCorrectnessTracking(r *binaryReader) correctnessTracking {
	tracking := correctnessTracking{
		magnitudeBound: r.f64(),
		errorBound:     r.f64(),
	}
	flag := r.u8()
	if flag > 1 {
		r.err = fmt.Errorf("invalid tracked-range flag")
	}
	tracking.rangeExceeded = flag == 1
	if tracking.magnitudeBound < 0 || math.IsNaN(tracking.magnitudeBound) || math.IsInf(tracking.magnitudeBound, 0) ||
		tracking.errorBound < 0 || math.IsNaN(tracking.errorBound) || math.IsInf(tracking.errorBound, 0) {
		r.err = fmt.Errorf("invalid correctness tracking bounds")
	}
	return tracking
}

func writePolyQP(w *binaryWriter, value rlwe.PolyQP) { writePoly(w, value.Q); writePoly(w, value.P) }
func readPolyQP(r *binaryReader) rlwe.PolyQP         { return rlwe.PolyQP{Q: readPoly(r), P: readPoly(r)} }

func validatePolyModuli(poly *ring.Poly, moduli []uint64, allowPrefix bool) error {
	if poly == nil || len(poly.Coeffs) == 0 || len(poly.Coeffs) > len(moduli) {
		return fmt.Errorf("invalid polynomial modulus count")
	}
	if !allowPrefix && len(poly.Coeffs) != len(moduli) {
		return fmt.Errorf("polynomial has %d moduli, expected %d", len(poly.Coeffs), len(moduli))
	}
	for level, coefficients := range poly.Coeffs {
		if len(coefficients) == 0 {
			return fmt.Errorf("polynomial has an empty coefficient vector")
		}
		for _, coefficient := range coefficients {
			if coefficient >= moduli[level] {
				return fmt.Errorf("polynomial coefficient is not reduced modulo level %d", level)
			}
		}
	}
	return nil
}

func validatePolyQ(ctx *nativeContext, poly *ring.Poly, allowPrefix bool) error {
	if err := validatePolyModuli(poly, ctx.params.Q(), allowPrefix); err != nil {
		return err
	}
	for _, coefficients := range poly.Coeffs {
		if len(coefficients) != ctx.params.N() {
			return fmt.Errorf("polynomial degree mismatch")
		}
	}
	return nil
}

func validatePolyQP(ctx *nativeContext, value rlwe.PolyQP) error {
	if err := validatePolyQ(ctx, value.Q, false); err != nil {
		return fmt.Errorf("Q polynomial: %w", err)
	}
	if err := validatePolyModuli(value.P, ctx.params.P(), false); err != nil {
		return fmt.Errorf("P polynomial: %w", err)
	}
	for _, coefficients := range value.P.Coeffs {
		if len(coefficients) != ctx.params.N() {
			return fmt.Errorf("P polynomial degree mismatch")
		}
	}
	return nil
}

func validateSwitchingKey(ctx *nativeContext, key *mkrlwe.SwitchingKey) error {
	if key == nil || len(key.Value) != ctx.params.Beta(ctx.params.MaxLevel()) {
		return fmt.Errorf("invalid switching-key decomposition length")
	}
	for _, value := range key.Value {
		if err := validatePolyQP(ctx, value); err != nil {
			return err
		}
	}
	return nil
}

func validateRelinearizationKey(ctx *nativeContext, key *mkrlwe.RelinearizationKey) error {
	if key == nil {
		return nil
	}
	if err := validatePartyID(key.ID); err != nil {
		return err
	}
	for _, switchingKey := range key.Value {
		if err := validateSwitchingKey(ctx, switchingKey); err != nil {
			return err
		}
	}
	return nil
}

func validateRotationKey(ctx *nativeContext, key *mkrlwe.RotationKey) error {
	if key == nil {
		return fmt.Errorf("nil rotation key")
	}
	if err := validatePartyID(key.ID); err != nil {
		return err
	}
	if key.RotIdx == 0 || int(key.RotIdx) >= ctx.params.Slots() {
		return fmt.Errorf("rotation index is outside slot bounds")
	}
	return validateSwitchingKey(ctx, key.Value)
}

func validateConjugationKey(ctx *nativeContext, key *mkrlwe.ConjugationKey) error {
	if key == nil {
		return nil
	}
	if err := validatePartyID(key.ID); err != nil {
		return err
	}
	return validateSwitchingKey(ctx, key.Value)
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func writeSwitchingKey(w *binaryWriter, key *mkrlwe.SwitchingKey) {
	if key == nil {
		w.u8(0)
		return
	}
	w.u8(1)
	w.u32(uint32(len(key.Value)))
	for _, value := range key.Value {
		writePolyQP(w, value)
	}
}

func readSwitchingKey(r *binaryReader) *mkrlwe.SwitchingKey {
	if r.u8() == 0 {
		return nil
	}
	count := r.u32()
	if count > 1<<16 {
		r.err = fmt.Errorf("invalid switching-key length")
		return nil
	}
	key := &mkrlwe.SwitchingKey{Value: make([]rlwe.PolyQP, count)}
	for i := range key.Value {
		key.Value[i] = readPolyQP(r)
	}
	return key
}

func writeContextPayload(ctx *nativeContext) ([]byte, error) {
	w := new(binaryWriter)
	literal, _ := json.Marshal(ctx.literal)
	w.bytes(literal)
	w.u32(uint32(ctx.workers))
	keys := make([]int, 0, len(ctx.params.CRS))
	for key := range ctx.params.CRS {
		keys = append(keys, key)
	}
	sort.Ints(keys)
	w.u32(uint32(len(keys)))
	for _, key := range keys {
		w.i64(int64(key))
		writeSwitchingKey(w, ctx.params.CRS[key])
	}
	return w.Bytes(), w.err
}

func readContextPayload(payload []byte) (*nativeContext, error) {
	r := newBinaryReader(payload)
	literal := r.bytes(1 << 20)
	workers := int(r.u32())
	count := r.u32()
	if count > 1<<16 {
		return nil, fmt.Errorf("invalid CRS count")
	}
	ctx, err := newContext(literal, workers)
	if err != nil {
		return nil, err
	}
	crs := make(map[int]*mkrlwe.SwitchingKey, count)
	for i := uint32(0); i < count; i++ {
		index := int(r.i64())
		if _, exists := crs[index]; exists {
			return nil, fmt.Errorf("duplicate CRS index %d", index)
		}
		key := readSwitchingKey(r)
		if err := validateSwitchingKey(ctx, key); err != nil {
			return nil, fmt.Errorf("invalid CRS index %d: %w", index, err)
		}
		crs[index] = key
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	ctx.params.CRS = crs
	required := []int{0, -1, -2, -3, -4}
	for bit := 1; bit < ctx.params.N()/2; bit <<= 1 {
		required = append(required, bit)
	}
	if len(crs) != len(required) {
		return nil, fmt.Errorf("CRS contains %d entries, expected %d", len(crs), len(required))
	}
	for _, index := range required {
		if _, ok := crs[index]; !ok {
			return nil, fmt.Errorf("CRS is missing required index %d", index)
		}
	}
	ctx.fingerprint = contextFingerprint(ctx)
	return ctx, nil
}

func writePartyPayload(party *nativeParty) ([]byte, error) {
	w := new(binaryWriter)
	w.string(party.sk.ID)
	writePolyQP(w, party.sk.Value)
	writePolyQP(w, party.pk.Value[0])
	writePolyQP(w, party.pk.Value[1])
	return w.Bytes(), w.err
}

func readPartyPayload(ctx *nativeContext, payload []byte) (*nativeParty, error) {
	r := newBinaryReader(payload)
	id := r.string(128)
	if err := validatePartyID(id); err != nil {
		return nil, err
	}
	sk := mkrlwe.NewSecretKey(ctx.params.Parameters, id)
	sk.Value = readPolyQP(r)
	pk := mkrlwe.NewPublicKey(ctx.params.Parameters, id)
	pk.Value[0], pk.Value[1] = readPolyQP(r), readPolyQP(r)
	if err := r.done(); err != nil {
		return nil, err
	}
	if err := validatePolyQP(ctx, sk.Value); err != nil {
		return nil, fmt.Errorf("invalid secret key: %w", err)
	}
	for _, value := range pk.Value {
		if err := validatePolyQP(ctx, value); err != nil {
			return nil, fmt.Errorf("invalid public key: %w", err)
		}
	}
	if err := reservePartyID(ctx, id); err != nil {
		return nil, err
	}
	return &nativeParty{ctx: ctx, sk: sk, pk: pk}, nil
}

func writePublicKeyPayload(public *nativePublicKey) ([]byte, error) {
	w := new(binaryWriter)
	w.string(public.pk.ID)
	writePolyQP(w, public.pk.Value[0])
	writePolyQP(w, public.pk.Value[1])
	return w.Bytes(), w.err
}

func readPublicKeyPayload(ctx *nativeContext, payload []byte) (*nativePublicKey, error) {
	r := newBinaryReader(payload)
	id := r.string(128)
	if err := validatePartyID(id); err != nil {
		return nil, err
	}
	pk := mkrlwe.NewPublicKey(ctx.params.Parameters, id)
	pk.Value[0], pk.Value[1] = readPolyQP(r), readPolyQP(r)
	if err := r.done(); err != nil {
		return nil, err
	}
	for _, value := range pk.Value {
		if err := validatePolyQP(ctx, value); err != nil {
			return nil, fmt.Errorf("invalid public key: %w", err)
		}
	}
	return &nativePublicKey{ctx: ctx, pk: pk}, nil
}

func writeCipherPayload(cipher *nativeCiphertext) ([]byte, error) {
	w := new(binaryWriter)
	w.u64(uint64(cipher.length))
	if cipher.isComplex {
		w.u8(1)
	} else {
		w.u8(0)
	}
	w.raw(cipher.artifact[:])
	writeCorrectnessTracking(w, cipher.tracking)
	w.u32(uint32(len(cipher.chunks)))
	for _, chunk := range cipher.chunks {
		w.f64(chunk.Scale)
		ids := make([]string, 0, len(chunk.Value))
		for id := range chunk.Value {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		w.u32(uint32(len(ids)))
		for _, id := range ids {
			w.string(id)
			writePoly(w, chunk.Value[id])
		}
	}
	return w.Bytes(), w.err
}

func readCipherPayload(ctx *nativeContext, payload []byte) (*nativeCiphertext, error) {
	r := newBinaryReader(payload)
	result := &nativeCiphertext{ctx: ctx, length: int(r.u64()), isComplex: r.u8() != 0}
	_, r.err = io.ReadFull(r.Reader, result.artifact[:])
	result.tracking = readCorrectnessTracking(r)
	count := r.u32()
	if count == 0 || count > 1<<20 {
		return nil, fmt.Errorf("invalid ciphertext chunk count")
	}
	result.chunks = make([]*mkckks.Ciphertext, count)
	var expectedIDs []string
	expectedModuli := 0
	expectedScale := 0.0
	for i := range result.chunks {
		scale := r.f64()
		if !isFinitePositive(scale) {
			return nil, fmt.Errorf("invalid ciphertext scale")
		}
		if i == 0 {
			expectedScale = scale
		} else if scale != expectedScale {
			return nil, fmt.Errorf("ciphertext chunks have inconsistent scales")
		}
		componentCount := r.u32()
		if componentCount == 0 || componentCount > 1<<16 {
			return nil, fmt.Errorf("invalid component count")
		}
		value := make(map[string]*ring.Poly, componentCount)
		for j := uint32(0); j < componentCount; j++ {
			id := r.string(128)
			if id != "0" {
				if err := validatePartyID(id); err != nil {
					return nil, err
				}
			}
			if _, exists := value[id]; exists {
				return nil, fmt.Errorf("duplicate ciphertext component %q", id)
			}
			poly := readPoly(r)
			if err := validatePolyQ(ctx, poly, true); err != nil {
				return nil, fmt.Errorf("invalid ciphertext component %q: %w", id, err)
			}
			if expectedModuli == 0 {
				expectedModuli = len(poly.Coeffs)
			} else if len(poly.Coeffs) != expectedModuli {
				return nil, fmt.Errorf("ciphertext components have inconsistent levels")
			}
			value[id] = poly
		}
		if _, ok := value["0"]; !ok {
			return nil, fmt.Errorf("ciphertext is missing component 0")
		}
		ids := make([]string, 0, len(value))
		for id := range value {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		if i == 0 {
			expectedIDs = ids
		} else if !equalStrings(ids, expectedIDs) {
			return nil, fmt.Errorf("ciphertext chunks have inconsistent participant sets")
		}
		result.chunks[i] = &mkckks.Ciphertext{Ciphertext: &mkrlwe.Ciphertext{Value: value}, Scale: scale}
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	if result.length <= 0 || result.length > 1<<26 || (result.length+ctx.params.Slots()-1)/ctx.params.Slots() != len(result.chunks) {
		return nil, fmt.Errorf("invalid ciphertext logical length")
	}
	if !result.tracking.rangeExceeded && trackedRangeMargin(
		ctx, result.chunks[0].Level(), result.chunks[0].Scale, result.tracking,
	) < 0 {
		return nil, fmt.Errorf("ciphertext range metadata is inconsistent")
	}
	return result, nil
}

func writePlaintextPayload(plaintext *nativePlaintext) ([]byte, error) {
	w := new(binaryWriter)
	w.u64(uint64(plaintext.length))
	if plaintext.isComplex {
		w.u8(1)
	} else {
		w.u8(0)
	}
	writeCorrectnessTracking(w, plaintext.tracking)
	w.u32(uint32(len(plaintext.values)))
	for _, chunk := range plaintext.values {
		w.u32(uint32(len(chunk)))
		for _, value := range chunk {
			w.f64(real(value))
			w.f64(imag(value))
		}
	}
	return w.Bytes(), w.err
}

func readPlaintextPayload(ctx *nativeContext, payload []byte) (*nativePlaintext, error) {
	r := newBinaryReader(payload)
	result := &nativePlaintext{ctx: ctx, length: int(r.u64()), isComplex: r.u8() != 0}
	result.tracking = readCorrectnessTracking(r)
	count := r.u32()
	if count == 0 || count > 1<<20 {
		return nil, fmt.Errorf("invalid plaintext chunks")
	}
	result.values = make([][]complex128, count)
	for i := range result.values {
		n := r.u32()
		if n != uint32(ctx.params.Slots()) {
			return nil, fmt.Errorf("invalid plaintext slot count")
		}
		result.values[i] = make([]complex128, n)
		for j := range result.values[i] {
			realValue, imagValue := r.f64(), r.f64()
			if math.IsNaN(realValue) || math.IsInf(realValue, 0) || math.IsNaN(imagValue) || math.IsInf(imagValue, 0) {
				return nil, fmt.Errorf("plaintext contains a non-finite value")
			}
			result.values[i][j] = complex(realValue, imagValue)
		}
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	if result.length <= 0 || result.length > 1<<26 || (result.length+ctx.params.Slots()-1)/ctx.params.Slots() != len(result.values) {
		return nil, fmt.Errorf("invalid plaintext logical length")
	}
	expectedTracking := plaintextTracking(ctx, result.values)
	if result.tracking != expectedTracking {
		return nil, fmt.Errorf("plaintext correctness metadata does not match its values")
	}
	return result, nil
}

func writeSharePayload(share *nativeShare) ([]byte, error) {
	w := new(binaryWriter)
	w.string(share.partyID)
	w.raw(share.cipherID[:])
	w.u64(uint64(share.length))
	w.u32(uint32(len(share.deltas)))
	for _, delta := range share.deltas {
		writePoly(w, delta)
	}
	return w.Bytes(), w.err
}

func readSharePayload(ctx *nativeContext, payload []byte) (*nativeShare, error) {
	r := newBinaryReader(payload)
	result := &nativeShare{ctx: ctx, partyID: r.string(128)}
	if err := validatePartyID(result.partyID); err != nil {
		return nil, err
	}
	_, r.err = io.ReadFull(r.Reader, result.cipherID[:])
	result.length = int(r.u64())
	count := r.u32()
	if count == 0 || count > 1<<20 {
		return nil, fmt.Errorf("invalid share chunks")
	}
	result.deltas = make([]*ring.Poly, count)
	expectedModuli := 0
	for i := range result.deltas {
		result.deltas[i] = readPoly(r)
		if err := validatePolyQ(ctx, result.deltas[i], true); err != nil {
			return nil, fmt.Errorf("invalid decryption-share polynomial: %w", err)
		}
		if expectedModuli == 0 {
			expectedModuli = len(result.deltas[i].Coeffs)
		} else if len(result.deltas[i].Coeffs) != expectedModuli {
			return nil, fmt.Errorf("decryption-share chunks have inconsistent levels")
		}
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	if result.length <= 0 || result.length > 1<<26 || (result.length+ctx.params.Slots()-1)/ctx.params.Slots() != len(result.deltas) {
		return nil, fmt.Errorf("invalid decryption-share logical length")
	}
	return result, nil
}

func writeRelinearizationKey(w *binaryWriter, key *mkrlwe.RelinearizationKey) {
	if key == nil {
		w.u8(0)
		return
	}
	w.u8(1)
	w.string(key.ID)
	for _, v := range key.Value {
		writeSwitchingKey(w, v)
	}
}
func readRelinearizationKey(r *binaryReader) *mkrlwe.RelinearizationKey {
	if r.u8() == 0 {
		return nil
	}
	k := &mkrlwe.RelinearizationKey{ID: r.string(128)}
	for i := range k.Value {
		k.Value[i] = readSwitchingKey(r)
	}
	return k
}
func writeRotationKey(w *binaryWriter, key *mkrlwe.RotationKey) {
	w.string(key.ID)
	w.u64(uint64(key.RotIdx))
	writeSwitchingKey(w, key.Value)
}
func readRotationKey(r *binaryReader) *mkrlwe.RotationKey {
	return &mkrlwe.RotationKey{ID: r.string(128), RotIdx: uint(r.u64()), Value: readSwitchingKey(r)}
}
func writeConjugationKey(w *binaryWriter, key *mkrlwe.ConjugationKey) {
	if key == nil {
		w.u8(0)
		return
	}
	w.u8(1)
	w.string(key.ID)
	writeSwitchingKey(w, key.Value)
}
func readConjugationKey(r *binaryReader) *mkrlwe.ConjugationKey {
	if r.u8() == 0 {
		return nil
	}
	return &mkrlwe.ConjugationKey{ID: r.string(128), Value: readSwitchingKey(r)}
}

func writeEvalContributionPayload(value *nativeEvalContribution) ([]byte, error) {
	w := new(binaryWriter)
	w.string(value.id)
	writeRelinearizationKey(w, value.rlin)
	keys := make([]int, 0, len(value.rotations))
	for k := range value.rotations {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	w.u32(uint32(len(keys)))
	for _, k := range keys {
		w.i64(int64(k))
		writeRotationKey(w, value.rotations[k])
	}
	writeConjugationKey(w, value.conj)
	return w.Bytes(), w.err
}
func readEvalContributionPayload(ctx *nativeContext, payload []byte) (*nativeEvalContribution, error) {
	r := newBinaryReader(payload)
	v := &nativeEvalContribution{ctx: ctx, id: r.string(128), rlin: readRelinearizationKey(r), rotations: make(map[int]*mkrlwe.RotationKey)}
	if err := validatePartyID(v.id); err != nil {
		return nil, err
	}
	if err := validateRelinearizationKey(ctx, v.rlin); err != nil {
		return nil, fmt.Errorf("invalid relinearization key: %w", err)
	}
	if v.rlin != nil && v.rlin.ID != v.id {
		return nil, fmt.Errorf("relinearization-key participant mismatch")
	}
	count := r.u32()
	if count > 1<<16 {
		return nil, fmt.Errorf("invalid rotation-key count")
	}
	for i := uint32(0); i < count; i++ {
		index64 := r.i64()
		if index64 <= 0 || index64 >= int64(ctx.params.Slots()) {
			return nil, fmt.Errorf("rotation index is outside slot bounds")
		}
		index := int(index64)
		if _, exists := v.rotations[index]; exists {
			return nil, fmt.Errorf("duplicate rotation index %d", index)
		}
		key := readRotationKey(r)
		if err := validateRotationKey(ctx, key); err != nil {
			return nil, fmt.Errorf("invalid rotation key %d: %w", index, err)
		}
		if key.ID != v.id || key.RotIdx != uint(index) {
			return nil, fmt.Errorf("rotation-key metadata mismatch")
		}
		v.rotations[index] = key
	}
	v.conj = readConjugationKey(r)
	if err := r.done(); err != nil {
		return nil, err
	}
	if err := validateConjugationKey(ctx, v.conj); err != nil {
		return nil, fmt.Errorf("invalid conjugation key: %w", err)
	}
	if v.conj != nil && v.conj.ID != v.id {
		return nil, fmt.Errorf("conjugation-key participant mismatch")
	}
	return v, nil
}

func writeEvalSetPayload(value *nativeEvalSet) ([]byte, error) {
	w := new(binaryWriter)
	ids := make([]string, 0, len(value.ids))
	for id := range value.ids {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	w.u32(uint32(len(ids)))
	for _, id := range ids {
		w.string(id)
		writeRelinearizationKey(w, value.rlin.Value[id])
		rots := value.rot.Value[id]
		keys := make([]int, 0, len(rots))
		for k := range rots {
			keys = append(keys, int(k))
		}
		sort.Ints(keys)
		w.u32(uint32(len(keys)))
		for _, k := range keys {
			writeRotationKey(w, rots[uint(k)])
		}
		writeConjugationKey(w, value.conj.Value[id])
	}
	return w.Bytes(), w.err
}
func readEvalSetPayload(ctx *nativeContext, payload []byte) (*nativeEvalSet, error) {
	r := newBinaryReader(payload)
	v := &nativeEvalSet{ctx: ctx, rlin: mkrlwe.NewRelinearizationKeyKeySet(ctx.params.Parameters), rot: mkrlwe.NewRotationKeySet(), conj: mkrlwe.NewConjugationKeySet(), ids: make(map[string]struct{})}
	count := r.u32()
	if count == 0 || count > 1<<16 {
		return nil, fmt.Errorf("invalid evaluation participant count")
	}
	for i := uint32(0); i < count; i++ {
		id := r.string(128)
		if err := validatePartyID(id); err != nil {
			return nil, err
		}
		if _, exists := v.ids[id]; exists {
			return nil, fmt.Errorf("duplicate evaluation-key participant %q", id)
		}
		v.ids[id] = struct{}{}
		if key := readRelinearizationKey(r); key != nil {
			if err := validateRelinearizationKey(ctx, key); err != nil {
				return nil, fmt.Errorf("invalid relinearization key for %q: %w", id, err)
			}
			if key.ID != id {
				return nil, fmt.Errorf("relinearization-key participant mismatch")
			}
			v.rlin.AddRelinearizationKey(key)
		}
		rotCount := r.u32()
		if rotCount > 1<<16 {
			return nil, fmt.Errorf("invalid rotation count")
		}
		seenRotations := make(map[uint]struct{}, rotCount)
		for j := uint32(0); j < rotCount; j++ {
			key := readRotationKey(r)
			if err := validateRotationKey(ctx, key); err != nil {
				return nil, fmt.Errorf("invalid rotation key for %q: %w", id, err)
			}
			if key.ID != id {
				return nil, fmt.Errorf("rotation-key participant mismatch")
			}
			if _, exists := seenRotations[key.RotIdx]; exists {
				return nil, fmt.Errorf("duplicate rotation index %d for %q", key.RotIdx, id)
			}
			seenRotations[key.RotIdx] = struct{}{}
			v.rot.AddRotationKey(key)
		}
		if key := readConjugationKey(r); key != nil {
			if err := validateConjugationKey(ctx, key); err != nil {
				return nil, fmt.Errorf("invalid conjugation key for %q: %w", id, err)
			}
			if key.ID != id {
				return nil, fmt.Errorf("conjugation-key participant mismatch")
			}
			v.conj.AddConjugationKey(key)
		}
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	return v, nil
}

func serializeEntry(entry registryEntry) ([]byte, error) {
	var fp string
	var payload []byte
	var err error
	switch entry.kind {
	case kindContext:
		ctx := entry.value.(*nativeContext)
		fp = ctx.fingerprint
		payload, err = writeContextPayload(ctx)
	case kindParty:
		v := entry.value.(*nativeParty)
		fp = v.ctx.fingerprint
		payload, err = writePartyPayload(v)
	case kindPublicKey:
		v := entry.value.(*nativePublicKey)
		fp = v.ctx.fingerprint
		payload, err = writePublicKeyPayload(v)
	case kindCiphertext:
		v := entry.value.(*nativeCiphertext)
		fp = v.ctx.fingerprint
		payload, err = writeCipherPayload(v)
	case kindPlaintext:
		v := entry.value.(*nativePlaintext)
		fp = v.ctx.fingerprint
		payload, err = writePlaintextPayload(v)
	case kindShare:
		v := entry.value.(*nativeShare)
		fp = v.ctx.fingerprint
		payload, err = writeSharePayload(v)
	case kindEvalContribution:
		v := entry.value.(*nativeEvalContribution)
		fp = v.ctx.fingerprint
		payload, err = writeEvalContributionPayload(v)
	case kindEvalSet:
		v := entry.value.(*nativeEvalSet)
		fp = v.ctx.fingerprint
		payload, err = writeEvalSetPayload(v)
	default:
		return nil, fmt.Errorf("unsupported artifact kind")
	}
	if err != nil {
		return nil, err
	}
	return wrapArtifact(entry.kind, fp, payload)
}

func deserializeEntry(context *nativeContext, data []byte) (registryEntry, error) {
	kind, fp, payload, err := unwrapArtifact(data)
	if err != nil {
		return registryEntry{}, err
	}
	if kind == kindContext {
		ctx, err := readContextPayload(payload)
		if err != nil {
			return registryEntry{}, err
		}
		if ctx.fingerprint != fp {
			return registryEntry{}, fmt.Errorf("context fingerprint mismatch")
		}
		return registryEntry{kind: kindContext, value: ctx}, nil
	}
	if context == nil {
		return registryEntry{}, fmt.Errorf("a context is required to import this artifact")
	}
	if context.fingerprint != fp {
		return registryEntry{}, fmt.Errorf("artifact context fingerprint mismatch")
	}
	var value interface{}
	switch kind {
	case kindParty:
		value, err = readPartyPayload(context, payload)
	case kindPublicKey:
		value, err = readPublicKeyPayload(context, payload)
	case kindCiphertext:
		value, err = readCipherPayload(context, payload)
	case kindPlaintext:
		value, err = readPlaintextPayload(context, payload)
	case kindShare:
		value, err = readSharePayload(context, payload)
	case kindEvalContribution:
		value, err = readEvalContributionPayload(context, payload)
	case kindEvalSet:
		value, err = readEvalSetPayload(context, payload)
	default:
		err = fmt.Errorf("unsupported artifact kind %d", kind)
	}
	return registryEntry{kind: kind, value: value}, err
}
