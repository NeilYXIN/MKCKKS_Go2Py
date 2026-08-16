// SPDX-License-Identifier: MIT
package main

/*
#include <stdint.h>
#include <stdlib.h>
*/
import "C"

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"mk-lattigo/mkrlwe"
	"runtime"
	"sort"
	"sync"
	"unsafe"
)

type nativeStatusError struct {
	code      int
	operation string
	message   string
}

func (err *nativeStatusError) Error() string {
	if err.operation == "" {
		return err.message
	}
	return err.operation + ": " + err.message
}

func statusFailure(code int, operation, message string) error {
	return &nativeStatusError{code: code, operation: operation, message: message}
}

const (
	statusOK       = 0
	statusInvalid  = 1
	statusHandle   = 2
	statusContext  = 3
	statusKey      = 4
	statusLevel    = 5
	statusSerial   = 6
	statusShare    = 7
	statusNative   = 255
	abiVersion     = 1
	maxInputValues = 1 << 26
)

// nativeCallLease prevents close from releasing or wiping an object while any
// exported operation is using registry-backed values. Release takes the
// exclusive side; ordinary calls take the shared side.
var nativeCallLease sync.RWMutex

func runExport(errorOut **C.char, fn func() (int, error)) (status C.int32_t) {
	nativeCallLease.RLock()
	defer nativeCallLease.RUnlock()
	return executeExport(errorOut, fn)
}

func runExclusiveExport(errorOut **C.char, fn func() (int, error)) (status C.int32_t) {
	nativeCallLease.Lock()
	defer nativeCallLease.Unlock()
	return executeExport(errorOut, fn)
}

func executeExport(errorOut **C.char, fn func() (int, error)) (status C.int32_t) {
	if errorOut != nil {
		*errorOut = nil
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			status = statusNative
			if errorOut != nil {
				*errorOut = C.CString(fmt.Sprintf("native panic recovered: %v", recovered))
			}
		}
	}()
	code, err := fn()
	if err != nil {
		var typed *nativeStatusError
		if errors.As(err, &typed) {
			code = typed.code
		}
		if code == 0 {
			code = statusNative
		}
		if errorOut != nil {
			*errorOut = C.CString(err.Error())
		}
		return C.int32_t(code)
	}
	return statusOK
}

func writeHandle(output *C.uint64_t, handle uint64) error {
	if output == nil {
		return statusFailure(statusInvalid, "native ABI", "output handle is NULL")
	}
	*output = C.uint64_t(handle)
	return nil
}

func registerObject(output *C.uint64_t, kind objectKind, value interface{}) error {
	if output == nil {
		return statusFailure(statusInvalid, "native ABI", "output handle is NULL")
	}
	return writeHandle(output, putObject(kind, value))
}

func validateFlag(value C.uint8_t, name string) error {
	if value != 0 && value != 1 {
		return statusFailure(statusInvalid, name, "Boolean flag must be 0 or 1")
	}
	return nil
}

func bytesFromC(pointer unsafe.Pointer, size C.size_t) ([]byte, error) {
	if uint64(size) > maxInputValues*16 {
		return nil, fmt.Errorf("input buffer too large")
	}
	if size == 0 {
		return []byte{}, nil
	}
	if pointer == nil {
		return nil, fmt.Errorf("input buffer is NULL")
	}
	return C.GoBytes(pointer, C.int(size)), nil
}

func doublesFromC(pointer *C.double, size int) ([]float64, error) {
	if size <= 0 || size > maxInputValues {
		return nil, fmt.Errorf("array length must be between 1 and %d", maxInputValues)
	}
	if pointer == nil {
		return nil, fmt.Errorf("array pointer is NULL")
	}
	values := (*[maxInputValues]C.double)(unsafe.Pointer(pointer))[:size:size]
	result := make([]float64, size)
	for i := range values {
		result[i] = float64(values[i])
		if math.IsNaN(result[i]) || math.IsInf(result[i], 0) {
			return nil, fmt.Errorf("array contains a non-finite value at index %d", i)
		}
	}
	return result, nil
}

func handlesFromC(pointer *C.uint64_t, size int) ([]uint64, error) {
	if size == 0 {
		return []uint64{}, nil
	}
	if size < 0 || size > 1<<20 || pointer == nil {
		return nil, fmt.Errorf("invalid handle array")
	}
	values := (*[1 << 20]C.uint64_t)(unsafe.Pointer(pointer))[:size:size]
	result := make([]uint64, size)
	for i := range values {
		result[i] = uint64(values[i])
	}
	return result, nil
}

func intsFromC(pointer *C.int32_t, size int) ([]int, error) {
	if size == 0 {
		return nil, nil
	}
	if size < 0 || size > 1<<20 || pointer == nil {
		return nil, fmt.Errorf("invalid integer array")
	}
	values := (*[1 << 20]C.int32_t)(unsafe.Pointer(pointer))[:size:size]
	result := make([]int, size)
	for i := range values {
		result[i] = int(values[i])
	}
	return result, nil
}

func returnBytes(data []byte, output **C.uint8_t, outputSize *C.size_t) error {
	if output == nil || outputSize == nil {
		return statusFailure(statusInvalid, "native ABI", "output buffer pointers are NULL")
	}
	if len(data) == 0 {
		*output = nil
		*outputSize = 0
		return nil
	}
	pointer := C.CBytes(data)
	if pointer == nil {
		return fmt.Errorf("native allocation failed")
	}
	*output = (*C.uint8_t)(pointer)
	*outputSize = C.size_t(len(data))
	return nil
}

func contextForHandle(handle uint64) (*nativeContext, error) {
	value, err := getObject(handle, kindContext)
	if err != nil {
		return nil, err
	}
	return value.(*nativeContext), nil
}

func partyForHandle(handle uint64) (*nativeParty, error) {
	value, err := getObject(handle, kindParty)
	if err != nil {
		return nil, err
	}
	return value.(*nativeParty), nil
}

func cipherForHandle(handle uint64) (*nativeCiphertext, error) {
	value, err := getObject(handle, kindCiphertext)
	if err != nil {
		return nil, err
	}
	return value.(*nativeCiphertext), nil
}

func evalSetForHandle(handle uint64) (*nativeEvalSet, error) {
	value, err := getObject(handle, kindEvalSet)
	if err != nil {
		return nil, err
	}
	return value.(*nativeEvalSet), nil
}

func metadataForEntry(entry registryEntry) map[string]interface{} {
	metadata := map[string]interface{}{"kind": uint8(entry.kind)}
	switch entry.kind {
	case kindContext:
		value := entry.value.(*nativeContext)
		metadata["context_fingerprint"] = value.fingerprint
		metadata["slots"] = value.params.Slots()
		metadata["max_level"] = value.params.MaxLevel()
	case kindParty:
		value := entry.value.(*nativeParty)
		metadata["context_fingerprint"] = value.ctx.fingerprint
		metadata["party_id"] = value.sk.ID
		metadata["key_fingerprint"] = hex.EncodeToString(value.identity[:])
	case kindPublicKey:
		value := entry.value.(*nativePublicKey)
		metadata["context_fingerprint"] = value.ctx.fingerprint
		metadata["party_id"] = value.pk.ID
		metadata["key_fingerprint"] = hex.EncodeToString(value.identity[:])
	case kindEvalContribution:
		value := entry.value.(*nativeEvalContribution)
		metadata["context_fingerprint"] = value.ctx.fingerprint
		metadata["party_id"] = value.id
		metadata["key_fingerprint"] = hex.EncodeToString(value.identity[:])
	case kindEvalSet:
		value := entry.value.(*nativeEvalSet)
		ids := make([]string, 0, len(value.identities))
		participantKeys := make(map[string]string, len(value.identities))
		for id, identity := range value.identities {
			ids = append(ids, id)
			participantKeys[id] = hex.EncodeToString(identity[:])
		}
		sort.Strings(ids)
		metadata["context_fingerprint"] = value.ctx.fingerprint
		metadata["participants"] = ids
		metadata["participant_keys"] = participantKeys
	case kindPlaintext:
		value := entry.value.(*nativePlaintext)
		metadata["context_fingerprint"] = value.ctx.fingerprint
		metadata["length"] = value.length
		metadata["complex"] = value.isComplex
		metadata["chunks"] = len(value.values)
		metadata["tracked_magnitude_bound"] = value.tracking.magnitudeBound
		metadata["tracked_error_bound"] = value.tracking.errorBound
		metadata["range_exceeded"] = value.tracking.rangeExceeded
		metadata["range_margin_bits"] = trackedRangeMargin(
			value.ctx, value.ctx.params.MaxLevel(), value.ctx.params.Scale(), value.tracking,
		)
	case kindCiphertext:
		value := entry.value.(*nativeCiphertext)
		metadata["context_fingerprint"] = value.ctx.fingerprint
		metadata["length"] = value.length
		metadata["complex"] = value.isComplex
		metadata["chunks"] = len(value.chunks)
		metadata["level"] = value.chunks[0].Level()
		metadata["scale"] = value.chunks[0].Scale
		metadata["participants"] = participantIDs(value)
		participantKeys := make(map[string]string, len(value.identities))
		for id, identity := range value.identities {
			participantKeys[id] = hex.EncodeToString(identity[:])
		}
		metadata["participant_keys"] = participantKeys
		metadata["artifact_id"] = hex.EncodeToString(value.artifact[:])
		metadata["tracked_magnitude_bound"] = value.tracking.magnitudeBound
		metadata["tracked_error_bound"] = value.tracking.errorBound
		metadata["range_exceeded"] = value.tracking.rangeExceeded
		metadata["range_margin_bits"] = trackedRangeMargin(
			value.ctx, value.chunks[0].Level(), value.chunks[0].Scale, value.tracking,
		)
	case kindShare:
		value := entry.value.(*nativeShare)
		metadata["context_fingerprint"] = value.ctx.fingerprint
		metadata["party_id"] = value.partyID
		metadata["key_fingerprint"] = hex.EncodeToString(value.identity[:])
		metadata["artifact_id"] = hex.EncodeToString(value.cipherID[:])
		metadata["length"] = value.length
		metadata["chunks"] = len(value.deltas)
	}
	return metadata
}

//export mkckks_v1_abi_version
func mkckks_v1_abi_version() C.uint32_t { return abiVersion }

//export mkckks_v1_build_info
func mkckks_v1_build_info(output **C.uint8_t, outputSize *C.size_t, errorOut **C.char) C.int32_t {
	return runExport(errorOut, func() (int, error) {
		info := map[string]interface{}{
			"abi_version":     abiVersion,
			"go_version":      runtime.Version(),
			"goos":            runtime.GOOS,
			"goarch":          runtime.GOARCH,
			"upstream_commit": upstreamCommit,
		}
		data, err := json.Marshal(info)
		if err != nil {
			return statusNative, err
		}
		return statusOK, returnBytes(data, output, outputSize)
	})
}

//export mkckks_v1_buffer_free
func mkckks_v1_buffer_free(pointer unsafe.Pointer) {
	if pointer != nil {
		C.free(pointer)
	}
}

//export mkckks_v1_error_free
func mkckks_v1_error_free(pointer *C.char) {
	if pointer != nil {
		C.free(unsafe.Pointer(pointer))
	}
}

//export mkckks_v1_live_handles
func mkckks_v1_live_handles() C.uint64_t { return C.uint64_t(liveObjectCount()) }

//export mkckks_v1_release
func mkckks_v1_release(handle C.uint64_t, errorOut **C.char) C.int32_t {
	return runExclusiveExport(errorOut, func() (int, error) {
		if err := releaseObject(uint64(handle)); err != nil {
			return statusHandle, err
		}
		return statusOK, nil
	})
}

//export mkckks_v1_context_create
func mkckks_v1_context_create(literal *C.uint8_t, literalSize C.size_t, workers C.int32_t, output *C.uint64_t, errorOut **C.char) C.int32_t {
	return runExport(errorOut, func() (int, error) {
		if output == nil {
			return statusInvalid, fmt.Errorf("output handle is NULL")
		}
		raw, err := bytesFromC(unsafe.Pointer(literal), literalSize)
		if err != nil {
			return statusInvalid, err
		}
		ctx, err := newContext(raw, int(workers))
		if err != nil {
			return statusInvalid, err
		}
		return statusOK, registerObject(output, kindContext, ctx)
	})
}

//export mkckks_v1_context_info
func mkckks_v1_context_info(handle C.uint64_t, output **C.uint8_t, outputSize *C.size_t, errorOut **C.char) C.int32_t {
	return runExport(errorOut, func() (int, error) {
		ctx, err := contextForHandle(uint64(handle))
		if err != nil {
			return statusHandle, err
		}
		info := map[string]interface{}{
			"fingerprint": ctx.fingerprint,
			"slots":       ctx.params.Slots(),
			"workers":     ctx.workers,
			"max_level":   ctx.params.MaxLevel(),
			"scale":       ctx.params.Scale(),
			"parameters":  ctx.literal,
		}
		data, err := json.Marshal(info)
		if err != nil {
			return statusNative, err
		}
		return statusOK, returnBytes(data, output, outputSize)
	})
}

//export mkckks_v1_party_generate
func mkckks_v1_party_generate(contextHandle C.uint64_t, partyID *C.uint8_t, partyIDSize C.size_t, output *C.uint64_t, errorOut **C.char) C.int32_t {
	return runExport(errorOut, func() (int, error) {
		if output == nil {
			return statusInvalid, fmt.Errorf("output handle is NULL")
		}
		ctx, err := contextForHandle(uint64(contextHandle))
		if err != nil {
			return statusHandle, err
		}
		raw, err := bytesFromC(unsafe.Pointer(partyID), partyIDSize)
		if err != nil {
			return statusInvalid, err
		}
		party, err := generateParty(ctx, string(raw))
		if err != nil {
			return statusInvalid, err
		}
		return statusOK, registerObject(output, kindParty, party)
	})
}

//export mkckks_v1_party_public_key
func mkckks_v1_party_public_key(partyHandle C.uint64_t, output *C.uint64_t, errorOut **C.char) C.int32_t {
	return runExport(errorOut, func() (int, error) {
		party, err := partyForHandle(uint64(partyHandle))
		if err != nil {
			return statusHandle, err
		}
		return statusOK, registerObject(output, kindPublicKey, &nativePublicKey{
			ctx: party.ctx, pk: clonePublicKey(party.pk), identity: party.identity,
		})
	})
}

func readInputArrays(realPointer, imagPointer *C.double, length int, isComplex bool) ([]float64, []float64, error) {
	realValues, err := doublesFromC(realPointer, length)
	if err != nil {
		return nil, nil, err
	}
	var imagValues []float64
	if isComplex {
		imagValues, err = doublesFromC(imagPointer, length)
		if err != nil {
			return nil, nil, err
		}
	}
	return realValues, imagValues, nil
}

//export mkckks_v1_encrypt
func mkckks_v1_encrypt(keyHandle C.uint64_t, realPointer, imagPointer *C.double, length C.size_t, isComplex C.uint8_t, output *C.uint64_t, errorOut **C.char) C.int32_t {
	return runExport(errorOut, func() (int, error) {
		if err := validateFlag(isComplex, "encrypt complex flag"); err != nil {
			return statusInvalid, err
		}
		entry, err := getAnyObject(uint64(keyHandle))
		if err != nil {
			return statusHandle, err
		}
		var ctx *nativeContext
		var pk *mkrlwe.PublicKey
		switch entry.kind {
		case kindParty:
			party := entry.value.(*nativeParty)
			ctx, pk = party.ctx, party.pk
		case kindPublicKey:
			public := entry.value.(*nativePublicKey)
			ctx, pk = public.ctx, public.pk
		default:
			return statusHandle, fmt.Errorf("encryption requires a Party or PublicKey handle")
		}
		realValues, imagValues, err := readInputArrays(realPointer, imagPointer, int(length), isComplex != 0)
		if err != nil {
			return statusInvalid, err
		}
		ciphertext, err := encryptValues(ctx, pk, splitValues(ctx, realValues, imagValues, isComplex != 0), int(length), isComplex != 0)
		if err != nil {
			return statusNative, err
		}
		return statusOK, registerObject(output, kindCiphertext, ciphertext)
	})
}

//export mkckks_v1_encode_plaintext
func mkckks_v1_encode_plaintext(contextHandle C.uint64_t, realPointer, imagPointer *C.double, length C.size_t, isComplex C.uint8_t, output *C.uint64_t, errorOut **C.char) C.int32_t {
	return runExport(errorOut, func() (int, error) {
		if err := validateFlag(isComplex, "plaintext complex flag"); err != nil {
			return statusInvalid, err
		}
		ctx, err := contextForHandle(uint64(contextHandle))
		if err != nil {
			return statusHandle, err
		}
		realValues, imagValues, err := readInputArrays(realPointer, imagPointer, int(length), isComplex != 0)
		if err != nil {
			return statusInvalid, err
		}
		plaintext := encodeValues(ctx, splitValues(ctx, realValues, imagValues, isComplex != 0), int(length), isComplex != 0)
		return statusOK, registerObject(output, kindPlaintext, plaintext)
	})
}

func binaryExport(operation string, leftHandle, rightHandle C.uint64_t, output *C.uint64_t, errorOut **C.char) C.int32_t {
	return runExport(errorOut, func() (int, error) {
		left, err := cipherForHandle(uint64(leftHandle))
		if err != nil {
			return statusHandle, err
		}
		right, err := cipherForHandle(uint64(rightHandle))
		if err != nil {
			return statusHandle, err
		}
		result, err := binaryCipher(operation, left, right)
		if err != nil {
			return statusContext, err
		}
		return statusOK, registerObject(output, kindCiphertext, result)
	})
}

//export mkckks_v1_add
func mkckks_v1_add(left, right C.uint64_t, output *C.uint64_t, errorOut **C.char) C.int32_t {
	return binaryExport("add", left, right, output, errorOut)
}

//export mkckks_v1_subtract
func mkckks_v1_subtract(left, right C.uint64_t, output *C.uint64_t, errorOut **C.char) C.int32_t {
	return binaryExport("sub", left, right, output, errorOut)
}

//export mkckks_v1_add_scalar
func mkckks_v1_add_scalar(inputHandle C.uint64_t, realValue, imagValue C.double, subtract C.uint8_t, output *C.uint64_t, errorOut **C.char) C.int32_t {
	return runExport(errorOut, func() (int, error) {
		if err := validateFlag(subtract, "scalar subtraction flag"); err != nil {
			return statusInvalid, err
		}
		input, err := cipherForHandle(uint64(inputHandle))
		if err != nil {
			return statusHandle, err
		}
		if math.IsNaN(float64(realValue)) || math.IsInf(float64(realValue), 0) || math.IsNaN(float64(imagValue)) || math.IsInf(float64(imagValue), 0) {
			return statusInvalid, fmt.Errorf("scalar must be finite")
		}
		result, err := addScalarCipher(input, complex(float64(realValue), float64(imagValue)), subtract != 0)
		if err != nil {
			return statusNative, err
		}
		return statusOK, registerObject(output, kindCiphertext, result)
	})
}

//export mkckks_v1_add_plaintext
func mkckks_v1_add_plaintext(inputHandle, plaintextHandle C.uint64_t, subtract C.uint8_t, output *C.uint64_t, errorOut **C.char) C.int32_t {
	return runExport(errorOut, func() (int, error) {
		if err := validateFlag(subtract, "plaintext subtraction flag"); err != nil {
			return statusInvalid, err
		}
		input, err := cipherForHandle(uint64(inputHandle))
		if err != nil {
			return statusHandle, err
		}
		value, err := getObject(uint64(plaintextHandle), kindPlaintext)
		if err != nil {
			return statusHandle, err
		}
		result, err := addPlaintextCipher(input, value.(*nativePlaintext), subtract != 0)
		if err != nil {
			return statusContext, err
		}
		return statusOK, registerObject(output, kindCiphertext, result)
	})
}

//export mkckks_v1_multiply_scalar
func mkckks_v1_multiply_scalar(inputHandle C.uint64_t, realPart, imagPart C.double, output *C.uint64_t, errorOut **C.char) C.int32_t {
	return runExport(errorOut, func() (int, error) {
		input, err := cipherForHandle(uint64(inputHandle))
		if err != nil {
			return statusHandle, err
		}
		if math.IsNaN(float64(realPart)) || math.IsInf(float64(realPart), 0) || math.IsNaN(float64(imagPart)) || math.IsInf(float64(imagPart), 0) {
			return statusInvalid, fmt.Errorf("scalar must be finite")
		}
		result, err := scalarCipher(input, complex(float64(realPart), float64(imagPart)))
		if err != nil {
			return statusNative, err
		}
		return statusOK, registerObject(output, kindCiphertext, result)
	})
}

//export mkckks_v1_multiply_plaintext
func mkckks_v1_multiply_plaintext(cipherHandle, plaintextHandle C.uint64_t, output *C.uint64_t, errorOut **C.char) C.int32_t {
	return runExport(errorOut, func() (int, error) {
		ciphertext, err := cipherForHandle(uint64(cipherHandle))
		if err != nil {
			return statusHandle, err
		}
		value, err := getObject(uint64(plaintextHandle), kindPlaintext)
		if err != nil {
			return statusHandle, err
		}
		result, err := plaintextCipher(ciphertext, value.(*nativePlaintext))
		if err != nil {
			return statusContext, err
		}
		return statusOK, registerObject(output, kindCiphertext, result)
	})
}

//export mkckks_v1_party_evaluation_keys
func mkckks_v1_party_evaluation_keys(partyHandle C.uint64_t, relinearization C.uint8_t, rotations *C.int32_t, rotationCount C.size_t, conjugation C.uint8_t, output *C.uint64_t, errorOut **C.char) C.int32_t {
	return runExport(errorOut, func() (int, error) {
		if err := validateFlag(relinearization, "relinearization flag"); err != nil {
			return statusInvalid, err
		}
		if err := validateFlag(conjugation, "conjugation flag"); err != nil {
			return statusInvalid, err
		}
		party, err := partyForHandle(uint64(partyHandle))
		if err != nil {
			return statusHandle, err
		}
		rotationValues, err := intsFromC(rotations, int(rotationCount))
		if err != nil {
			return statusInvalid, err
		}
		contribution, err := generateEvalContribution(party, relinearization != 0, rotationValues, conjugation != 0)
		if err != nil {
			return statusKey, err
		}
		return statusOK, registerObject(output, kindEvalContribution, contribution)
	})
}

//export mkckks_v1_evaluation_keys_combine
func mkckks_v1_evaluation_keys_combine(handles *C.uint64_t, count C.size_t, output *C.uint64_t, errorOut **C.char) C.int32_t {
	return runExport(errorOut, func() (int, error) {
		values, err := handlesFromC(handles, int(count))
		if err != nil {
			return statusInvalid, err
		}
		contributions := make([]*nativeEvalContribution, len(values))
		for i, handle := range values {
			value, err := getObject(handle, kindEvalContribution)
			if err != nil {
				return statusHandle, err
			}
			contributions[i] = value.(*nativeEvalContribution)
		}
		combined, err := combineEvalContributions(contributions)
		if err != nil {
			return statusKey, err
		}
		return statusOK, registerObject(output, kindEvalSet, combined)
	})
}

//export mkckks_v1_multiply
func mkckks_v1_multiply(keyHandle, leftHandle, rightHandle C.uint64_t, hoisted C.uint8_t, output *C.uint64_t, errorOut **C.char) C.int32_t {
	return runExport(errorOut, func() (int, error) {
		if err := validateFlag(hoisted, "multiplication hoisted flag"); err != nil {
			return statusInvalid, err
		}
		keys, err := evalSetForHandle(uint64(keyHandle))
		if err != nil {
			return statusHandle, err
		}
		left, err := cipherForHandle(uint64(leftHandle))
		if err != nil {
			return statusHandle, err
		}
		right, err := cipherForHandle(uint64(rightHandle))
		if err != nil {
			return statusHandle, err
		}
		result, err := multiplyCipher(left, right, keys, hoisted != 0)
		if err != nil {
			return statusKey, err
		}
		return statusOK, registerObject(output, kindCiphertext, result)
	})
}

func levelExport(operation string, inputHandle C.uint64_t, value float64, output *C.uint64_t, errorOut **C.char) C.int32_t {
	return runExport(errorOut, func() (int, error) {
		input, err := cipherForHandle(uint64(inputHandle))
		if err != nil {
			return statusHandle, err
		}
		result, err := levelCipher(input, operation, value)
		if err != nil {
			return statusLevel, err
		}
		return statusOK, registerObject(output, kindCiphertext, result)
	})
}

//export mkckks_v1_drop_level
func mkckks_v1_drop_level(inputHandle C.uint64_t, levels C.int32_t, output *C.uint64_t, errorOut **C.char) C.int32_t {
	return levelExport("drop", inputHandle, float64(levels), output, errorOut)
}

//export mkckks_v1_rescale
func mkckks_v1_rescale(inputHandle C.uint64_t, minimumScale C.double, output *C.uint64_t, errorOut **C.char) C.int32_t {
	return levelExport("rescale", inputHandle, float64(minimumScale), output, errorOut)
}

//export mkckks_v1_rotate
func mkckks_v1_rotate(keyHandle, inputHandle C.uint64_t, rotation C.int32_t, hoisted C.uint8_t, output *C.uint64_t, errorOut **C.char) C.int32_t {
	return runExport(errorOut, func() (int, error) {
		if err := validateFlag(hoisted, "rotation hoisted flag"); err != nil {
			return statusInvalid, err
		}
		input, err := cipherForHandle(uint64(inputHandle))
		if err != nil {
			return statusHandle, err
		}
		var keys *nativeEvalSet
		normalized := int(rotation) % input.ctx.params.Slots()
		if normalized < 0 {
			normalized += input.ctx.params.Slots()
		}
		if normalized != 0 {
			keys, err = evalSetForHandle(uint64(keyHandle))
			if err != nil {
				return statusHandle, err
			}
		}
		result, err := rotateCipher(input, keys, int(rotation), hoisted != 0)
		if err != nil {
			return statusKey, err
		}
		return statusOK, registerObject(output, kindCiphertext, result)
	})
}

//export mkckks_v1_conjugate
func mkckks_v1_conjugate(keyHandle, inputHandle C.uint64_t, output *C.uint64_t, errorOut **C.char) C.int32_t {
	return runExport(errorOut, func() (int, error) {
		keys, err := evalSetForHandle(uint64(keyHandle))
		if err != nil {
			return statusHandle, err
		}
		input, err := cipherForHandle(uint64(inputHandle))
		if err != nil {
			return statusHandle, err
		}
		result, err := conjugateCipher(input, keys)
		if err != nil {
			return statusKey, err
		}
		return statusOK, registerObject(output, kindCiphertext, result)
	})
}

//export mkckks_v1_partial_decrypt
func mkckks_v1_partial_decrypt(partyHandle, cipherHandle C.uint64_t, output *C.uint64_t, errorOut **C.char) C.int32_t {
	return runExport(errorOut, func() (int, error) {
		party, err := partyForHandle(uint64(partyHandle))
		if err != nil {
			return statusHandle, err
		}
		ciphertext, err := cipherForHandle(uint64(cipherHandle))
		if err != nil {
			return statusHandle, err
		}
		share, err := partialDecrypt(party, ciphertext)
		if err != nil {
			return statusContext, err
		}
		return statusOK, registerObject(output, kindShare, share)
	})
}

//export mkckks_v1_collective_decrypt
func mkckks_v1_collective_decrypt(cipherHandle C.uint64_t, shareHandles *C.uint64_t, shareCount C.size_t, realOutput, imagOutput *C.double, outputLength C.size_t, errorOut **C.char) C.int32_t {
	return runExport(errorOut, func() (int, error) {
		ciphertext, err := cipherForHandle(uint64(cipherHandle))
		if err != nil {
			return statusHandle, err
		}
		handles, err := handlesFromC(shareHandles, int(shareCount))
		if err != nil {
			return statusInvalid, err
		}
		shares := make([]*nativeShare, len(handles))
		for i, handle := range handles {
			value, err := getObject(handle, kindShare)
			if err != nil {
				return statusHandle, err
			}
			shares[i] = value.(*nativeShare)
		}
		if uint64(outputLength) < uint64(ciphertext.length) || realOutput == nil || imagOutput == nil {
			return statusInvalid, fmt.Errorf("output arrays are NULL or too small")
		}
		values, err := collectiveDecrypt(ciphertext, shares)
		if err != nil {
			return statusShare, err
		}
		realSlice := (*[maxInputValues]C.double)(unsafe.Pointer(realOutput))[:ciphertext.length:ciphertext.length]
		imagSlice := (*[maxInputValues]C.double)(unsafe.Pointer(imagOutput))[:ciphertext.length:ciphertext.length]
		for i, value := range values {
			realSlice[i] = C.double(real(value))
			imagSlice[i] = C.double(imag(value))
		}
		return statusOK, nil
	})
}

//export mkckks_v1_cipher_metadata
func mkckks_v1_cipher_metadata(cipherHandle C.uint64_t, output **C.uint8_t, outputSize *C.size_t, errorOut **C.char) C.int32_t {
	return runExport(errorOut, func() (int, error) {
		entry, err := getAnyObject(uint64(cipherHandle))
		if err != nil {
			return statusHandle, err
		}
		if entry.kind != kindCiphertext {
			return statusHandle, fmt.Errorf("native handle is not a ciphertext")
		}
		data, err := json.Marshal(metadataForEntry(entry))
		if err != nil {
			return statusNative, err
		}
		return statusOK, returnBytes(data, output, outputSize)
	})
}

//export mkckks_v1_object_metadata
func mkckks_v1_object_metadata(handle C.uint64_t, output **C.uint8_t, outputSize *C.size_t, errorOut **C.char) C.int32_t {
	return runExport(errorOut, func() (int, error) {
		entry, err := getAnyObject(uint64(handle))
		if err != nil {
			return statusHandle, err
		}
		data, err := json.Marshal(metadataForEntry(entry))
		if err != nil {
			return statusNative, err
		}
		return statusOK, returnBytes(data, output, outputSize)
	})
}

//export mkckks_v1_export_artifact
func mkckks_v1_export_artifact(handle C.uint64_t, output **C.uint8_t, outputSize *C.size_t, errorOut **C.char) C.int32_t {
	return runExport(errorOut, func() (int, error) {
		entry, err := getAnyObject(uint64(handle))
		if err != nil {
			return statusHandle, err
		}
		data, err := serializeEntry(entry)
		if err != nil {
			return statusSerial, err
		}
		return statusOK, returnBytes(data, output, outputSize)
	})
}

//export mkckks_v1_import_artifact
func mkckks_v1_import_artifact(contextHandle C.uint64_t, dataPointer *C.uint8_t, dataSize C.size_t, output *C.uint64_t, outputKind *C.uint8_t, errorOut **C.char) C.int32_t {
	return runExport(errorOut, func() (int, error) {
		if output == nil || outputKind == nil {
			return statusInvalid, fmt.Errorf("artifact outputs are NULL")
		}
		data, err := bytesFromC(unsafe.Pointer(dataPointer), dataSize)
		if err != nil {
			return statusSerial, err
		}
		var ctx *nativeContext
		if contextHandle != 0 {
			ctx, err = contextForHandle(uint64(contextHandle))
			if err != nil {
				return statusHandle, err
			}
		}
		entry, err := deserializeEntry(ctx, data)
		if err != nil {
			return statusSerial, err
		}
		if err = registerObject(output, entry.kind, entry.value); err != nil {
			return statusInvalid, err
		}
		*outputKind = C.uint8_t(entry.kind)
		return statusOK, nil
	})
}

func main() {}
