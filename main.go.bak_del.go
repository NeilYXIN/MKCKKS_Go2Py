package main

import (
	"C"
	"flag"
	"fmt"
	"mk-lattigo/mkckks"
	"mk-lattigo/mkrlwe"
	"strconv"

	"github.com/ldsec/lattigo/v2/ckks"
	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/rlwe"
	"github.com/ldsec/lattigo/v2/utils"
)

type testParams struct {
	params mkckks.Parameters
	ringQ  *ring.Ring
	ringP  *ring.Ring
	prng   utils.PRNG
	kgen   *mkrlwe.KeyGenerator
	skSet  *mkrlwe.SecretKeySet
	pkSet  *mkrlwe.PublicKeySet
	rlkSet *mkrlwe.RelinearizationKeySet
	rtkSet *mkrlwe.RotationKeySet
	cjkSet *mkrlwe.ConjugationKeySet

	encryptor *mkckks.Encryptor
	decryptor *mkckks.Decryptor
	evaluator *mkckks.Evaluator
	idset     *mkrlwe.IDSet
}

var N = 2

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

		var testContext *testParams
		if testContext, err = genTestParams(params, idset); err != nil {
			panic(err)
		}

		for numUsers := 2; numUsers <= *maxUsers; numUsers *= 2 {
			benchMulAndRelin(testContext, userList[:numUsers])
			//benchMulAndRelinHoisted(testContext, userList[:numUsers], b)
			//benchSquareHoisted(testContext, userList[:numUsers], b)
		}

		/*

		   for numUsers := 2; numUsers <= maxUsers; numUsers *= 2 {
		       benchRotate(testContext, userList[:numUsers], b)
		   }

		*/

	}
}

func benchMulAndRelin(testContext *testParams, userList []string) {

	numUsers := len(userList)
	msgList := make([]*mkckks.Message, numUsers)
	ctList := make([]*mkckks.Ciphertext, numUsers)

	rlkSet := testContext.rlkSet
	eval := testContext.evaluator

	for i := range userList {
		msgList[i], ctList[i] = newTestVectors(testContext, userList[i], complex(-1, 1), complex(-1, 1))
	}

	ct0 := ctList[0]
	ct1 := ctList[0]

	for i := range userList {
		ct0 = eval.AddNew(ct0, ctList[i])
		ct1 = eval.SubNew(ct1, ctList[i])
	}

	// b.Run(GetTestName(testContext.params, "MKMulAndRelin: "+strconv.Itoa(numUsers)+"/ "), func() {
	//     for i := 0; i < N; i++ {
	//         eval.MulRelinNew(ct0, ct1, rlkSet)
	//     }

	// })
	fmt.Println("MKMulAndRelin: " + strconv.Itoa(numUsers) + "/ ")
	for i := 0; i < N; i++ {
		eval.MulRelinNew(ct0, ct1, rlkSet)
	}

}

func benchRotate(testContext *testParams, userList []string) {

	numUsers := len(userList)
	msgList := make([]*mkckks.Message, numUsers)
	ctList := make([]*mkckks.Ciphertext, numUsers)

	rtkSet := testContext.rtkSet
	eval := testContext.evaluator

	for i := range userList {
		msgList[i], ctList[i] = newTestVectors(testContext, userList[i], complex(-1, 1), complex(-1, 1))
	}

	ct := ctList[0]

	for i := range userList {
		ct = eval.AddNew(ct, ctList[i])
	}

	for i := 0; i < N; i++ {
		eval.RotateNew(ct, 2, rtkSet)
	}

}

func benchMulAndRelinHoisted(testContext *testParams, userList []string) {

	numUsers := len(userList)
	msgList := make([]*mkckks.Message, numUsers)
	ctList := make([]*mkckks.Ciphertext, numUsers)

	rlkSet := testContext.rlkSet
	eval := testContext.evaluator

	for i := range userList {
		msgList[i], ctList[i] = newTestVectors(testContext, userList[i], complex(-1, 1), complex(-1, 1))
	}

	ct0 := ctList[0]
	ct1 := ctList[1]

	for i := range userList {
		ct0 = eval.AddNew(ct0, ctList[i])
		ct1 = eval.SubNew(ct1, ctList[i])
	}

	// b.Run(GetTestName(testContext.params, "MKMulAndRelinHoisted: "+strconv.Itoa(numUsers)+"/ "), func() {
	//     for i := 0; i < N; i++ {
	//         ct0Hoisted := eval.HoistedForm(ct0)
	//         ct1Hoisted := eval.HoistedForm(ct1)
	//         eval.MulRelinHoistedNew(ct0, ct1, ct0Hoisted, ct1Hoisted, rlkSet)
	//     }

	// })

	for i := 0; i < N; i++ {
		ct0Hoisted := eval.HoistedForm(ct0)
		ct1Hoisted := eval.HoistedForm(ct1)
		eval.MulRelinHoistedNew(ct0, ct1, ct0Hoisted, ct1Hoisted, rlkSet)
	}

}

func benchSquareHoisted(testContext *testParams, userList []string) {

	numUsers := len(userList)
	msgList := make([]*mkckks.Message, numUsers)
	ctList := make([]*mkckks.Ciphertext, numUsers)

	rlkSet := testContext.rlkSet
	eval := testContext.evaluator

	for i := range userList {
		msgList[i], ctList[i] = newTestVectors(testContext, userList[i], complex(-1, 1), complex(-1, 1))
	}

	ct := ctList[0]

	for i := range userList {
		ct = eval.AddNew(ct, ctList[i])
	}

	// b.Run(GetTestName(testContext.params, "SquareHoisted: "+strconv.Itoa(numUsers)+"/ "), func() {
	//     for i := 0; i < N; i++ {
	//         ctHoisted := eval.HoistedForm(ct)
	//         eval.MulRelinHoistedNew(ct, ct, ctHoisted, ctHoisted, rlkSet)
	//     }

	// })
	for i := 0; i < N; i++ {
		ctHoisted := eval.HoistedForm(ct)
		eval.MulRelinHoistedNew(ct, ct, ctHoisted, ctHoisted, rlkSet)
	}

}

func genTestParams(defaultParam mkckks.Parameters, idset *mkrlwe.IDSet) (testContext *testParams, err error) {

	testContext = new(testParams)

	testContext.params = defaultParam

	testContext.kgen = mkckks.NewKeyGenerator(testContext.params)

	testContext.skSet = mkrlwe.NewSecretKeySet()
	testContext.pkSet = mkrlwe.NewPublicKeyKeySet()
	testContext.rlkSet = mkrlwe.NewRelinearizationKeyKeySet(defaultParam.Parameters)
	testContext.rtkSet = mkrlwe.NewRotationKeySet()
	testContext.cjkSet = mkrlwe.NewConjugationKeySet()

	// gen sk, pk, rlk, rk

	for id := range idset.Value {
		sk, pk := testContext.kgen.GenKeyPair(id)
		r := testContext.kgen.GenSecretKey(id)
		rlk := testContext.kgen.GenRelinearizationKey(sk, r)
		//cjk := testContext.kgen.GenConjugationKey(sk)

		//testContext.kgen.GenDefaultRotationKeys(sk, testContext.rtkSet)

		testContext.skSet.AddSecretKey(sk)
		testContext.pkSet.AddPublicKey(pk)
		testContext.rlkSet.AddRelinearizationKey(rlk)
		//testContext.cjkSet.AddConjugationKey(cjk)

	}

	testContext.ringQ = defaultParam.RingQ()

	if testContext.prng, err = utils.NewPRNG(); err != nil {
		return nil, err
	}

	testContext.encryptor = mkckks.NewEncryptor(testContext.params)
	testContext.decryptor = mkckks.NewDecryptor(testContext.params)

	testContext.evaluator = mkckks.NewEvaluator(testContext.params)

	return testContext, nil

}

func newTestVectors(testContext *testParams, id string, a, b complex128) (msg *mkckks.Message, ciphertext *mkckks.Ciphertext) {

	params := testContext.params
	logSlots := testContext.params.LogSlots()

	msg = mkckks.NewMessage(params)

	for i := 0; i < 1<<logSlots; i++ {
		msg.Value[i] = complex(utils.RandFloat64(real(a), real(b)), utils.RandFloat64(imag(a), imag(b)))
	}

	if testContext.encryptor != nil {
		ciphertext = testContext.encryptor.EncryptMsgNew(msg, testContext.pkSet.GetPublicKey(id))
	} else {
		panic("cannot newTestVectors: encryptor is not initialized!")
	}

	return msg, ciphertext
}
