package main

/*
#include <stdbool.h>
#include <stddef.h>
#include <complex.h>

typedef struct {
	double* data;
	size_t size;
} Ldouble;

typedef struct {
	long long unsigned int* data;
	size_t size;
} Luint64;

// Message
typedef struct {
	double complex* data;
	size_t size;
} Message;

// Params
typedef struct {
	Luint64 qi;
	Luint64 pi;

    int logN;
	int logSlots;
	int gamma;

	double scale;
	double sigma;
} Params;

// ParametersLiteral
typedef struct {
	Luint64 qi;
	Luint64 pi;

    int logN;
	int logSlots;

	double scale;
	double sigma;
} ParametersLiteral;

// Poly
typedef struct {
	Luint64* coeffs;
	bool IsNTT;
	bool IsMForm;
	size_t size;
} Poly;

// PolyPair
typedef struct {
	Poly p0;
	Poly p1;
} PolyPair;

// PolyQP
typedef struct {
	Poly* Q;
	Poly* P;
} PolyQP;

// PolyQPPair
typedef struct {
	PolyQP qp0;
	PolyQP qp1;
} PolyQPPair;

// Share
typedef struct {
	Poly* data;
	size_t size;
} Share;

// Ciphertext
typedef struct {
	Poly* value;
	size_t size;
	int idx;

	double scale;
	// bool isNTT;
} Ciphertext;

// Data
typedef struct {
	Ciphertext* data;
	size_t size;
} Data;

// MPHEServer
typedef struct {
	// Params params;
	ParametersLiteral paramsLiteral;
	Poly crs;
	PolyQP sk;
	PolyQPPair pk;
	Data data;
	int idx;
} MPHEServer;

// MPHEClient
typedef struct {
	Params params;
	Poly crs;
	Poly secretKey;
	Poly publicKey;
	Poly decryptionKey;
} MPHEClient;
*/
import "C"
import (
	"flag"
	"fmt"
	"mk-lattigo/mkckks"
	"mk-lattigo/mkrlwe"
	"strconv"
	"unsafe"

	"github.com/ldsec/lattigo/v2/ckks"
	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/rlwe"
	"github.com/ldsec/lattigo/v2/utils"
)

type testParam struct {
	params mkckks.Parameters
	ringQ  *ring.Ring
	ringP  *ring.Ring
	prng   utils.PRNG
	kgen   *mkrlwe.KeyGenerator

	sk  *mkrlwe.SecretKey
	pk  *mkrlwe.PublicKey
	rlk *mkrlwe.RelinearizationKey
	// rtk *mkrlwe.RotationKey
	// cjk *mkrlwe.ConjugationKey

	// skSet  *mkrlwe.SecretKeySet
	// pkSet  *mkrlwe.PublicKeySet
	// rlkSet *mkrlwe.RelinearizationKeySet
	// rtkSet *mkrlwe.RotationKeySet
	// cjkSet *mkrlwe.ConjugationKeySet
	id string

	encryptor *mkckks.Encryptor
	decryptor *mkckks.Decryptor
	evaluator *mkckks.Evaluator
	// idset     *mkrlwe.IDSet
}

var N = 2
var PN14QP439 = ckks.ParametersLiteral{
	LogN:     14,
	LogSlots: 13,
	Q: []uint64{
		// 59 + 5x52
		0x7ffffffffe70001,

		0xffffffff00001, 0xfffffffe40001,
		0xfffffffe20001, 0xfffffffbe0001,
		0xfffffffa60001,
	},
	P: []uint64{
		// 60 x 2
		0xffffffffffc0001, 0xfffffffff840001,
	},
	Scale: 1 << 52,
	Sigma: rlwe.DefaultSigma,
}

//export newMPHEServer
func newMPHEServer(user_idx C.int) *C.MPHEServer {
	server := (*C.MPHEServer)(C.malloc(C.sizeof_MPHEServer))

	// func genTestContext(user_id int) *testParams {
	var (
		PN15QP880 = ckks.ParametersLiteral{
			LogN:     15,
			LogSlots: 14,
			//60 + 13x54
			Q: []uint64{
				0xfffffffff6a0001,

				0x3fffffffd60001, 0x3fffffffca0001,
				0x3fffffff6d0001, 0x3fffffff5d0001,
				0x3fffffff550001, 0x3fffffff390001,
				0x3fffffff360001, 0x3fffffff2a0001,
				0x3fffffff000001, 0x3ffffffefa0001,
				0x3ffffffef40001, 0x3ffffffed70001,
				0x3ffffffed30001,
			},
			P: []uint64{
				//59 x 2
				0x7ffffffffe70001, 0x7ffffffffe10001,
			},
			Scale: 1 << 54,
			Sigma: rlwe.DefaultSigma,
		}
		PN14QP439 = ckks.ParametersLiteral{
			LogN:     14,
			LogSlots: 13,
			Q: []uint64{
				// 59 + 5x52
				0x7ffffffffe70001,

				0xffffffff00001, 0xfffffffe40001,
				0xfffffffe20001, 0xfffffffbe0001,
				0xfffffffa60001,
			},
			P: []uint64{
				// 60 x 2
				0xffffffffffc0001, 0xfffffffff840001,
			},
			Scale: 1 << 52,
			Sigma: rlwe.DefaultSigma,
		}
	)

	// defaultParam := []ckks.ParametersLiteral{PN14QP439}
	PARAMSLITERAL := &[]ckks.ParametersLiteral{PN14QP439}[0] // hardcoded, assuming using one parameters lietral
	server.paramsLiteral = *convParamsLiteral(PARAMSLITERAL)

	ckksParams, err := ckks.NewParametersFromLiteral(*PARAMSLITERAL)
	if ckksParams.PCount() < 2 {
		fmt.Printf("ckks Params.PCount < 2")
		// continue
	}

	if err != nil {
		panic(err)
	}

	PARAMS := mkckks.NewParameters(ckksParams)

	// server.params = *convParams(&PARAMS)

	kgen := mkckks.NewKeyGenerator(PARAMS)

	// testContext.skSet = mkrlwe.NewSecretKeySet()

	// testContext.pkSet = mkrlwe.NewPublicKeyKeySet()
	// testContext.rlkSet = mkrlwe.NewRelinearizationKeyKeySet(defaultParam.Parameters)
	// testContext.rtkSet = mkrlwe.NewRotationKeySet()
	// testContext.cjkSet = mkrlwe.NewConjugationKeySet()

	// gen sk, pk, rlk, rk
	server.idx = user_idx // user_idx is C.int
	// user_id := "user" + strconv.Itoa(int(server.idx))
	user_id := strconv.Itoa(int(server.idx)) // C.int -> go int -> go string
	fmt.Printf(user_id)

	sk, pk := kgen.GenKeyPair(user_id)
	server.sk = *convPolyQP(&sk.SecretKey.Value)
	server.pk = *convPolyQPPair(pk.PublicKey.Value)

	r := kgen.GenSecretKey(user_id)
	rlk := kgen.GenRelinearizationKey(sk, r)
	// server.rlk = // TODO: rlk

	// userList := make([]string, maxUsers)
	// idset := mkrlwe.NewIDSet()

	// id := "user" + strconv.Itoa(user_id)

	// // for i := range userList {
	// // 	userList[i] = "user" + strconv.Itoa(i)
	// // 	idset.Add(userList[i])
	// // }

	// var testContext *testParam
	// if testContext, err = genTestParam(params, id); err != nil {
	// 	panic(err)
	// }
	return server
}

//export encryptFromPk
func encryptFromPk(pk *C.PolyQPPair, array *C.double, arraySize C.size_t, user_idx C.int) *C.Ciphertext {
	// func encryptFromPk(paramsLiteral *C.ParametersLiteral, pk *C.PolyQPPair, array *C.complexdouble, arraySize C.size_t, user_idx C.int) *C.Message {
	PARAMSLITERAL := &[]ckks.ParametersLiteral{PN14QP439}[0] // hardcoded, assuming using one parameters lietral
	// server.paramsLiteral = *convParamsLiteral(PARAMSLITERAL)

	ckksParams, err := ckks.NewParametersFromLiteral(*PARAMSLITERAL)

	// ckksParams, err := ckks.NewParametersFromLiteral(*paramsLiteral)
	if ckksParams.PCount() < 2 {
		fmt.Printf("ckks Params.PCount < 2")
		// continue
	}

	if err != nil {
		panic(err)
	}

	PARAMS := mkckks.NewParameters(ckksParams)

	// server.params = *convParams(&PARAMS)

	// kgen := mkckks.NewKeyGenerator(PARAMS)

	// params := convCKKSParams(parms)
	// encoder := ckks.NewEncoder(params)

	// publicKey := ckks.NewPublicKey(params)

	publicKey := mkrlwe.NewPublicKey(PARAMS.Parameters, strconv.Itoa(int(user_idx)))

	// pk.Value[0] = params.RingQP().NewPoly()
	// pk.Value[1] = params.RingQP().NewPoly()
	// pk.ID = id
	// publicKey.ID = strconv.Itoa(int(user_idx))

	// publicKey := ckks.NewPublicKey(params)
	pkPolyQP := convS2RingPolyQP(pk)
	publicKey.Value[0] = pkPolyQP[0].CopyNew()
	publicKey.Value[1] = pkPolyQP[1].CopyNew()

	// publicKey.Set(convS2RingPoly(pk))
	// encryptor := ckks.NewEncryptorFromPk(params, publicKey)

	// Encrypt the array element-wise
	size := int(arraySize)
	list := (*[1 << 30]C.double)(unsafe.Pointer(array))[:size:size]

	cts := new(mkckks.Ciphertext)
	msg := mkckks.NewMessage(PARAMS)

	for i, elem := range list {
		val := complex(float64(elem), 0.0)
		// val := complex(float64(elem), 0.0)
		msg.Value[i] = val
		// pt := encoder.EncodeNew([]complex128{val}, params.LogSlots())
		// cts[i] = encryptor.EncryptNew(pt)
	}
	encryptor := mkckks.NewEncryptor(PARAMS)

	cts = encryptor.EncryptMsgNew(msg, publicKey)

	// return convData(cts)
	return convCiphertext(cts)
}

//export decrypt
func decrypt(sk *C.PolyQP, ciphertext *C.Ciphertext, user_idx C.int) *C.Ldouble {

	PARAMSLITERAL := &[]ckks.ParametersLiteral{PN14QP439}[0] // hardcoded, assuming using one parameters lietral
	// server.paramsLiteral = *convParamsLiteral(PARAMSLITERAL)

	ckksParams, err := ckks.NewParametersFromLiteral(*PARAMSLITERAL)

	// ckksParams, err := ckks.NewParametersFromLiteral(*paramsLiteral)
	if ckksParams.PCount() < 2 {
		fmt.Printf("ckks Params.PCount < 2")
		// continue
	}

	if err != nil {
		panic(err)
	}

	PARAMS := mkckks.NewParameters(ckksParams)

	// params := convCKKSParams(parms)
	encoder := ckks.NewEncoder(params)

	secretKey := mkrlwe.NewSecretKey(PARAMS.Parameters, strconv.Itoa(int(user_idx)))

	skPolyQP := convRingPolyQP(sk)
	secretKey.Value = skPolyQP.CopyNew()
	// secretKey := ckks.NewSecretKey(params)
	// secretKey.Set(convRingPoly(sk))
	// decryptor := ckks.NewDecryptor(params, secretKey)
	decryptor := mkckks.NewDecryptor(PARAMS)
	// Decrypt the array element-wise
	// cts := convSckksCiphertext(data)
	cts := convMKCKKSCiphertext(ciphertext)
	values := make([]C.double, int(ciphertext.size))

	for i, ct := range cts {
		pt := decryptor.DecryptNew(ct)
		v := encoder.Decode(pt, params.LogSlots())[0]
		values[i] = C.double(real(v))
	}

	// Populate C.Ldouble
	array := (*C.Ldouble)(C.malloc(C.sizeof_Ldouble))

	array.data = (*C.double)(&values[0])
	array.size = C.size_t(len(values))

	return array
}

//export addCTs
func addCTs(op1 *C.Ciphertext, op2 *C.Ciphertext) *C.Ciphertext {
	PARAMSLITERAL := &[]ckks.ParametersLiteral{PN14QP439}[0] // hardcoded, assuming using one parameters lietral
	ckksParams, err := ckks.NewParametersFromLiteral(*PARAMSLITERAL)
	if ckksParams.PCount() < 2 {
		fmt.Printf("ckks Params.PCount < 2")
		// continue
	}

	if err != nil {
		panic(err)
	}

	PARAMS := mkckks.NewParameters(ckksParams)

	ct1 := convMKCKKSCiphertext(op1)
	ct2 := convMKCKKSCiphertext(op2)

	evaluator := mkckks.NewEvaluator(PARAMS)
	ct3 := evaluator.AddNew(ct1, ct2)

	return convCiphertext(ct3)
}

//export multiplyCTConst
func multiplyCTConst(op1 *C.Ciphertext, op2 C.double) *C.Ciphertext {
	PARAMSLITERAL := &[]ckks.ParametersLiteral{PN14QP439}[0] // hardcoded, assuming using one parameters lietral
	ckksParams, err := ckks.NewParametersFromLiteral(*PARAMSLITERAL)
	if ckksParams.PCount() < 2 {
		fmt.Printf("ckks Params.PCount < 2")
		// continue
	}

	if err != nil {
		panic(err)
	}

	PARAMS := mkckks.NewParameters(ckksParams)
	ct := convMKCKKSCiphertext(op1)
	constant := float64(op2)
	evaluator := mkckks.NewEvaluator(PARAMS)

	evaluator.MultByConst(ct, constant, ct)
	ct.Scale *= float64(constant)
	evaluator.Rescale(ct, PARAMS.Scale(), ct)
	return convCiphertext(ct)
}

func genTestParam(defaultParam mkckks.Parameters, user_id string) (testContext *testParam, err error) {

	testContext = new(testParam)

	testContext.params = defaultParam

	kgen := mkckks.NewKeyGenerator(testContext.params)

	// testContext.skSet = mkrlwe.NewSecretKeySet()

	// testContext.pkSet = mkrlwe.NewPublicKeyKeySet()
	// testContext.rlkSet = mkrlwe.NewRelinearizationKeyKeySet(defaultParam.Parameters)
	// testContext.rtkSet = mkrlwe.NewRotationKeySet()
	// testContext.cjkSet = mkrlwe.NewConjugationKeySet()

	// gen sk, pk, rlk, rk
	testContext.sk, testContext.pk = kgen.GenKeyPair(user_id)
	r := testContext.kgen.GenSecretKey(user_id)
	testContext.rlk = testContext.kgen.GenRelinearizationKey(testContext.sk, r)
	//cjk := testContext.kgen.GenConjugationKey(sk)

	//testContext.kgen.GenDefaultRotationKeys(sk, testContext.rtkSet)

	// testContext.skSet.AddSecretKey(sk)
	// testContext.pkSet.AddPublicKey(pk)
	// testContext.rlkSet.AddRelinearizationKey(rlk)
	//testContext.cjkSet.AddConjugationKey(cjk)

	// for id := range idset.Value {
	// 	sk, pk := testContext.kgen.GenKeyPair(id)
	// 	r := testContext.kgen.GenSecretKey(id)
	// 	rlk := testContext.kgen.GenRelinearizationKey(sk, r)
	// 	//cjk := testContext.kgen.GenConjugationKey(sk)

	// 	//testContext.kgen.GenDefaultRotationKeys(sk, testContext.rtkSet)

	// 	testContext.skSet.AddSecretKey(sk)
	// 	testContext.pkSet.AddPublicKey(pk)
	// 	testContext.rlkSet.AddRelinearizationKey(rlk)
	// 	//testContext.cjkSet.AddConjugationKey(cjk)

	// }

	testContext.ringQ = defaultParam.RingQ()

	if testContext.prng, err = utils.NewPRNG(); err != nil {
		return nil, err
	}

	testContext.encryptor = mkckks.NewEncryptor(testContext.params)
	testContext.decryptor = mkckks.NewDecryptor(testContext.params)

	testContext.evaluator = mkckks.NewEvaluator(testContext.params)

	return testContext, nil

}

//export main
func main() {
	// Get a random number between 0 and 99 inclusive.
	var maxUsers = flag.Int("n", 4, "maximum number of parties")

	var (
		PN15QP880 = ckks.ParametersLiteral{
			LogN:     15,
			LogSlots: 14,
			//60 + 13x54
			Q: []uint64{
				0xfffffffff6a0001,

				0x3fffffffd60001, 0x3fffffffca0001,
				0x3fffffff6d0001, 0x3fffffff5d0001,
				0x3fffffff550001, 0x3fffffff390001,
				0x3fffffff360001, 0x3fffffff2a0001,
				0x3fffffff000001, 0x3ffffffefa0001,
				0x3ffffffef40001, 0x3ffffffed70001,
				0x3ffffffed30001,
			},
			P: []uint64{
				//59 x 2
				0x7ffffffffe70001, 0x7ffffffffe10001,
			},
			Scale: 1 << 54,
			Sigma: rlwe.DefaultSigma,
		}
		PN14QP439 = ckks.ParametersLiteral{
			LogN:     14,
			LogSlots: 13,
			Q: []uint64{
				// 59 + 5x52
				0x7ffffffffe70001,

				0xffffffff00001, 0xfffffffe40001,
				0xfffffffe20001, 0xfffffffbe0001,
				0xfffffffa60001,
			},
			P: []uint64{
				// 60 x 2
				0xffffffffffc0001, 0xfffffffff840001,
			},
			Scale: 1 << 52,
			Sigma: rlwe.DefaultSigma,
		}
	)

	// defaultParams := []ckks.ParametersLiteral{PN14QP439, PN15QP880}
	defaultParams := []ckks.ParametersLiteral{PN14QP439, PN15QP880}

	for _, defaultParam := range defaultParams {
		ckksParams, err := ckks.NewParametersFromLiteral(defaultParam)

		if ckksParams.PCount() < 2 {
			continue
		}

		if err != nil {
			panic(err)
		}

		params := mkckks.NewParameters(ckksParams)
		userList := make([]string, *maxUsers)
		idset := mkrlwe.NewIDSet()

		for i := range userList {
			userList[i] = "user" + strconv.Itoa(i)
			idset.Add(userList[i])
		}
		user_id := "user" + strconv.Itoa(1)
		var testContext *testParam
		if testContext, err = genTestParam(params, user_id); err != nil {
			panic(err)
		}

		// for numUsers := 2; numUsers <= *maxUsers; numUsers *= 2 {
		// 	// benchMulAndRelin(testContext, userList[:numUsers])
		// 	//benchMulAndRelinHoisted(testContext, userList[:numUsers], b)
		// 	//benchSquareHoisted(testContext, userList[:numUsers], b)
		// }

		/*

		   for numUsers := 2; numUsers <= maxUsers; numUsers *= 2 {
		       benchRotate(testContext, userList[:numUsers], b)
		   }

		*/

	}
}

func newTestVectors(testContext *testParam, id string, a, b complex128) (msg *mkckks.Message, ciphertext *mkckks.Ciphertext) {

	params := testContext.params
	logSlots := testContext.params.LogSlots()

	msg = mkckks.NewMessage(params)

	for i := 0; i < 1<<logSlots; i++ {
		msg.Value[i] = complex(utils.RandFloat64(real(a), real(b)), utils.RandFloat64(imag(a), imag(b)))
	}

	if testContext.encryptor != nil {
		ciphertext = testContext.encryptor.EncryptMsgNew(msg, testContext.pk)
		// ciphertext = testContext.encryptor.EncryptMsgNew(msg, testContext.pkSet.GetPublicKey(id))
	} else {
		panic("cannot newTestVectors: encryptor is not initialized!")
	}

	return msg, ciphertext
}

/* HELPER: Conversion between C and Go structs */
// *ckks.ParametersLiteral --> *C.ParametersLiteral
func convParamsLiteral(p *ckks.ParametersLiteral) *C.ParametersLiteral {
	params_literal := (*C.ParametersLiteral)(C.malloc(C.sizeof_ParametersLiteral))

	// Populate struct
	qi := make([]uint64, len(p.Q))
	copy(qi, p.Q)
	params_literal.qi = convLuint64(qi)

	pi := make([]uint64, len(p.P))
	copy(pi, p.P)
	params_literal.pi = convLuint64(pi)

	params_literal.logN = C.int(p.LogN)
	params_literal.logSlots = C.int(p.LogSlots)

	params_literal.scale = C.double(p.Scale)
	params_literal.sigma = C.double(p.Sigma)

	return params_literal
}

// // *mkckks.Parameters --> *C.Params
// func convParams(p *mkckks.Parameters) *C.Params {
// 	params := (*C.Params)(C.malloc(C.sizeof_Params))

// 	// Populate struct
// 	qi := make([]uint64, len(p.qi))
// 	copy(qi, p.qi)
// 	params.qi = convLuint64(qi)

// 	pi := make([]uint64, len(p.pi))
// 	copy(pi, p.pi)
// 	params.pi = convLuint64(pi)

// 	params.logN = C.int(p.LogN())
// 	params.logSlots = C.int(p.LogSlots())
// 	params.gamma = C.int(2) // TODO: gamma = 2, hardcoded from mkrlwe.NewParameters()

// 	params.scale = C.double(p.Scale())
// 	params.sigma = C.double(p.Sigma())

// 	return params
// }

// // *C.Params --> *ckks.Parameters
// func convCKKSParams(params *C.Params) *ckks.Parameters {
// 	// Create Moduli struct wrapping slices qi, pi
// 	m := ckks.Moduli{
// 		Qi: convSuint64(params.qi),
// 		Pi: convSuint64(params.pi),
// 	}

// 	// Create and populate Params
// 	p, err := ckks.NewParametersFromModuli(uint64(params.logN), &m)

// 	if err != nil {
// 		fmt.Printf("C.Params built wrong: %v\n", err)
// 		return nil
// 	}

// 	p.SetLogSlots(uint64(params.logSlots))
// 	p.SetScale(float64(params.scale))
// 	p.SetSigma(float64(params.sigma))

// 	return p
// }

/// Message

// mkckks.Message --> C.Message
func convMessage(msg mkckks.Message) C.Message {
	list := (*C.Message)(C.malloc(C.sizeof_Message))

	// for i, comp_val := range msg.Value {
	// 	list.data

	// }

	list.data = (*C.complexdouble)(&msg.Value[0])
	list.size = C.size_t(len(msg.Value))

	return *list
}

// C.Message --> []complex128
func convMKCKKSMessage(list C.Message) *mkckks.Message {
	ret := new(mkckks.Message)
	size := int(list.size)
	vals := (*[1 << 30]complex128)(unsafe.Pointer(list.data))[:size:size]
	ret.Value = vals
	return ret
}

/// Luint64

// []uint64 --> Luint64
func convLuint64(vals []uint64) C.Luint64 {
	list := (*C.Luint64)(C.malloc(C.sizeof_Luint64))

	list.data = (*C.ulonglong)(&vals[0])
	list.size = C.size_t(len(vals))

	return *list
}

// Luint64 --> []uint64
func convSuint64(list C.Luint64) []uint64 {
	size := int(list.size)
	vals := (*[1 << 30]uint64)(unsafe.Pointer(list.data))[:size:size]

	return vals
}

/// Poly

// *ring.Poly --> *C.Poly
func convPoly(r *ring.Poly) *C.Poly {
	p := (*C.Poly)(C.malloc(C.sizeof_Poly))

	// Retrieve each coeff in a slice of C.Luint64
	coeffs := make([]C.Luint64, len(r.Coeffs))
	for i, coeff := range r.Coeffs {
		c := convLuint64(coeff)
		coeffs[i] = c
	}

	// Populate C.Poly
	p.coeffs = (*C.Luint64)(&coeffs[0])
	p.size = C.size_t(len(coeffs))

	return p
}

// *rlwe.PolyQP --> *C.PolyQP
func convPolyQP(r *rlwe.PolyQP) *C.PolyQP {
	qp := (*C.PolyQP)(C.malloc(C.sizeof_PolyQP))

	qp.Q = convPoly(r.Q)
	qp.P = convPoly(r.P)

	return qp
}

// TODO: reverse not finished
// *C.PolyQP --> *rlwe.PolyQP
func convRingPolyQP(qp *C.PolyQP) *rlwe.PolyQP {
	// // Extract coeffs as []Luint64
	// size := int(p.size)
	// list := (*[1 << 30]C.Luint64)(unsafe.Pointer(p.coeffs))[:size:size]

	// // Extract []uint64 from Luint64 to create [][]uint64
	// coeffs := make([][]uint64, size)
	// for i, coeff := range list {
	// 	c := convSuint64(coeff)
	// 	coeffs[i] = c
	// }

	// // Populate ring.Poly
	// r := new(ring.Poly)
	// r.Coeffs = coeffs

	ret := new(rlwe.PolyQP)

	ret.Q = convRingPoly(qp.Q)
	ret.P = convRingPoly(qp.P)

	return ret
}

// *C.Poly --> *ring.Poly
func convRingPoly(p *C.Poly) *ring.Poly {
	// Extract coeffs as []Luint64
	size := int(p.size)
	list := (*[1 << 30]C.Luint64)(unsafe.Pointer(p.coeffs))[:size:size]

	// Extract []uint64 from Luint64 to create [][]uint64
	coeffs := make([][]uint64, size)
	for i, coeff := range list {
		c := convSuint64(coeff)
		coeffs[i] = c
	}

	// Populate ring.Poly
	r := new(ring.Poly)
	r.Coeffs = coeffs

	return r
}

/// PolyPair

// [2]*ring.Poly --> *C.PolyPair
func convPolyPair(rpp [2]*ring.Poly) *C.PolyPair {
	pp := (*C.PolyPair)(C.malloc(C.sizeof_PolyPair))

	pp.p0 = *convPoly(rpp[0])
	pp.p1 = *convPoly(rpp[1])

	return pp
}

// *C.PolyPair --> [2]*ring.Poly
func convS2RingPoly(pp *C.PolyPair) [2]*ring.Poly {
	var rpp [2]*ring.Poly

	rpp[0] = convRingPoly(&pp.p0)
	rpp[1] = convRingPoly(&pp.p1)

	return rpp
}

/// PolyQPPair

// [2]*rlwe.PolyQP --> *C.PolyQPPair
func convPolyQPPair(rpp [2]rlwe.PolyQP) *C.PolyQPPair {
	qpp := (*C.PolyQPPair)(C.malloc(C.sizeof_PolyQPPair))

	qpp.qp0 = *convPolyQP(&rpp[0])
	qpp.qp1 = *convPolyQP(&rpp[1])

	return qpp
}

// *C.PolyQPPair --> [2]*rlwe.PolyQP
func convS2RingPolyQP(pp *C.PolyQPPair) [2]rlwe.PolyQP {
	var rpp [2]rlwe.PolyQP

	rpp[0] = *convRingPolyQP(&pp.qp0)
	rpp[1] = *convRingPolyQP(&pp.qp1)

	return rpp
}

/// Ciphertext

// *mkckks.Ciphertext --> *C.Ciphertext
func convCiphertext(cc *mkckks.Ciphertext) *C.Ciphertext {
	c := (*C.Ciphertext)(C.malloc(C.sizeof_Ciphertext))

	// Retrieve each polynomial making up the Ciphertext
	value := make([]C.Poly, len(cc.Value))
	if len(cc.Value) > 2 {
		fmt.Printf("ERROR: mkrlwe.Ciphertext contains map length > 2!")
	}
	counter := 0
	user_id := 0
	for key, val := range cc.Value {
		int_key, err := strconv.Atoi(key)
		if int_key != 0 {
			user_id = int_key
			if counter == 0 {
				fmt.Printf("ERROR: key with user_id was the first element in the map of mkrlwe.Ciphertext!")
			}
		}
		if err != nil {
			// ... handle error
			fmt.Printf("ERROR: Key in the map of mkrlwe.Ciphertext not a valid integer!")
			panic(err)
		}
		value[counter] = *convPoly(val)
		counter = counter + 1
	}

	// Populate C.Ciphertext
	c.value = (*C.Poly)(&value[0])
	c.size = C.size_t(len(value))
	c.idx = (C.int)(user_id)
	c.scale = C.double(cc.Scale)
	// c.isNTT = C.bool(cc.Element.IsNTT())

	return c
}

// // old
// func convCiphertext(cc *ckks.Ciphertext) *C.Ciphertext {
// 	c := (*C.Ciphertext)(C.malloc(C.sizeof_Ciphertext))

// 	// Retrieve each polynomial making up the Ciphertext
// 	value := make([]C.Poly, len(cc.Element.Value()))
// 	for i, val := range cc.Element.Value() {
// 		value[i] = *convPoly(val)
// 	}

// 	// Populate C.Ciphertext
// 	c.value = (*C.Poly)(&value[0])
// 	c.size = C.size_t(len(value))
// 	c.scale = C.double(cc.Element.Scale())
// 	c.isNTT = C.bool(cc.Element.IsNTT())

// 	return c
// }

// *C.Ciphertext --> *mkckks.Ciphertext
func convMKCKKSCiphertext(c *C.Ciphertext) *mkckks.Ciphertext {
	size := int(c.size)
	list := (*[1 << 30]C.Poly)(unsafe.Pointer(c.value))[:size:size]

	// Extract []*ringPoly from []C.Poly
	// value := make([]*ring.Poly, size)
	value := make(map[string]*ring.Poly)
	for i, poly := range list { // TODO: i is key, might not be user_idx
		v := convRingPoly(&poly)
		if i == 0 {
			value["0"] = v
		} else {
			value[strconv.Itoa(int(c.idx))] = v
		}
	}

	// Populate ckks.Ciphertext
	cc := new(mkckks.Ciphertext)
	// cc.Value = make(map[string]*ring.Poly)

	cc.Value = value
	cc.Scale = float64(c.scale)
	// cc.SetValue(value)
	// cc.Element.SetScale(float64(c.scale))
	// cc.Element.SetIsNTT(bool(c.isNTT))

	return cc
}

// // Old
// // *C.Ciphertext --> *ckks.Ciphertext
// func convCKKSCiphertext(c *C.Ciphertext) *ckks.Ciphertext {
// 	size := int(c.size)
// 	list := (*[1 << 30]C.Poly)(unsafe.Pointer(c.value))[:size:size]

// 	// Extract []*ringPoly from []C.Poly
// 	value := make([]*ring.Poly, size)
// 	for i, poly := range list {
// 		v := convRingPoly(&poly)
// 		value[i] = v
// 	}

// 	// Populate ckks.Ciphertext
// 	cc := new(ckks.Ciphertext)
// 	cc.Element = new(ckks.Element)

// 	cc.Element.SetValue(value)
// 	cc.Element.SetScale(float64(c.scale))
// 	cc.Element.SetIsNTT(bool(c.isNTT))

// 	return cc
// }

// /// Data
// // []*ckks.Ciphertext --> *C.Data
// func convData(sct []*mkrlwe.Ciphertext) *C.Data {
// 	data := (*C.Data)(C.malloc(C.sizeof_Data))

// 	// Retrieve pointer to slice
// 	ciphertexts := make([]C.Ciphertext, len(sct))
// 	for i, ct := range sct {
// 		ciphertexts[i] = *convCiphertext(ct)
// 	}

// 	data.data = (*C.Ciphertext)(&ciphertexts[0])
// 	data.size = C.size_t(len(sct))

// 	return data
// }

// // *C.Data --> []*ckks.Ciphertext
// func convSckksCiphertext(data *C.Data) []*mkrlwe.Ciphertext {
// 	size := int(data.size)
// 	cts := (*[1 << 30]C.Ciphertext)(unsafe.Pointer(data.data))[:size:size]

// 	// Extract []*ckks.Ciphertext from []C.Ciphertext
// 	cct := make([]*ckks.Ciphertext, size)
// 	for i, ciphertext := range cts {
// 		c := convMKRLWECiphertext(&ciphertext)
// 		cct[i] = c
// 	}

// 	return cct
// }

// // (*C.Data, C.size_t) --> [][]*ckks.Ciphertext
// func convSSckksCiphertext(datas *C.Data, datasSize C.size_t) [][]*ckks.Ciphertext {
// 	size := int(datasSize)
// 	data := (*[1 << 30]C.Data)(unsafe.Pointer(datas))[:size:size]

// 	// Extract [][]*ckks from []C.Data
// 	ccts := make([][]*ckks.Ciphertext, size)
// 	for i, ct := range data {
// 		ccts[i] = convSckksCiphertext(&ct)
// 	}

// 	return ccts
// }

/// Share

// *C.Share --> []*ring.Poly
func convSRingPoly(share *C.Share) []*ring.Poly {
	size := int(share.size)
	list := (*[1 << 30]C.Poly)(unsafe.Pointer(share.data))[:size:size]

	// Extract []*ringPoly from []C.Poly
	polys := make([]*ring.Poly, size)
	for i, poly := range list {
		polys[i] = convRingPoly(&poly)
	}

	return polys
}

// []*ring.Poly --> *C.Share
func convShare(polys []*ring.Poly) *C.Share {
	share := (*C.Share)(C.malloc(C.sizeof_Share))

	rps := make([]C.Poly, len(polys))
	for i, poly := range polys {
		rps[i] = *convPoly(poly)
	}

	share.data = (*C.Poly)(&rps[0])
	share.size = C.size_t(len(rps))

	return share
}

// (*C.Share, N C.size_t) --> [][]*ring.Poly (N rows, D cols)
func convSSRingPoly(shares *C.Share, sharesSize C.size_t) [][]*ring.Poly {
	size := int(sharesSize)
	list := (*[1 << 30]C.Share)(unsafe.Pointer(shares))[:size:size]

	// Extract []([]*ring.Poly) from []C.Share
	ssring := make([][]*ring.Poly, size)
	for i, share := range list {
		ssring[i] = convSRingPoly(&share)
	}

	// TODO: Error-check that all shares have the same number of polynomials
	// NOTE: in theory, one share per ciphertext

	return ssring
}
