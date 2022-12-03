package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm/lightclient"
	"github.com/ethereum/go-ethereum/rlp"
	iavl2 "github.com/tendermint/iavl"
	"github.com/tendermint/tendermint/crypto/merkle"
	"math/big"
)

var (
	// copied from go-ethereum source code: accounts/abi/abi_test.go
	Uint256, _    = abi.NewType("uint256", "", nil)
	Uint64, _     = abi.NewType("uint64", "", nil)
	Uint32, _     = abi.NewType("uint32", "", nil)
	Uint16, _     = abi.NewType("uint16", "", nil)
	String, _     = abi.NewType("string", "", nil)
	Bool, _       = abi.NewType("bool", "", nil)
	Bytes, _      = abi.NewType("bytes", "", nil)
	Bytes32, _    = abi.NewType("bytes32", "", nil)
	Address, _    = abi.NewType("address", "", nil)
	Uint64Arr, _  = abi.NewType("uint64[]", "", nil)
	AddressArr, _ = abi.NewType("address[]", "", nil)
	Int8, _       = abi.NewType("int8", "", nil)
	Uint8, _      = abi.NewType("uint8", "", nil)
	// Special types for testing
	Uint32Arr2, _       = abi.NewType("uint32[2]", "", nil)
	Uint64Arr2, _       = abi.NewType("uint64[2]", "", nil)
	Uint256Arr, _       = abi.NewType("uint256[]", "", nil)
	Uint256Arr2, _      = abi.NewType("uint256[2]", "", nil)
	Uint256Arr3, _      = abi.NewType("uint256[3]", "", nil)
	Uint256ArrNested, _ = abi.NewType("uint256[2][2]", "", nil)
	Uint8ArrNested, _   = abi.NewType("uint8[][2]", "", nil)
	Uint8SliceNested, _ = abi.NewType("uint8[][]", "", nil)
	TupleF, _           = abi.NewType("tuple", "struct Overloader.F", []abi.ArgumentMarshaling{
		{Name: "_f", Type: "uint256"},
		{Name: "__f", Type: "uint256"},
		{Name: "f", Type: "uint256"}})
)

func decodeProof(bz []byte) (*merkle.Proof, error) {
	var merkleProof merkle.Proof
	err := merkleProof.Unmarshal(bz)
	if err != nil {
		return nil, err
	}
	return &merkleProof, nil
}

type TransferOutSynPackage struct {
	TokenSymbol     [32]byte
	ContractAddress common.Address
	Amount          *big.Int
	Recipient       common.Address
	RefundAddress   common.Address
	ExpireTime      uint64
}

func decodePayload(payload string) (*TransferOutSynPackage, error) {
	bytest, _ := hex.DecodeString(payload)
	var pack TransferOutSynPackage
	err := rlp.DecodeBytes(bytest[33:], &pack)
	return &pack, err
}

// analyzeProof returns true if it founds an attacking transaction
func analyzeProof(txInputData []byte) (string, bool) {
	// unpack the tx input data
	callFunc := abi.NewMethod("handlePackage", "handlePackage", abi.Function, "", false, false,
		[]abi.Argument{
			{Name: "", Type: Bytes, Indexed: false},
			{Name: "", Type: Bytes, Indexed: false},
			{Name: "", Type: Uint64, Indexed: false},
			{Name: "", Type: Uint64, Indexed: false},
			{Name: "", Type: Uint8, Indexed: false},
		},
		[]abi.Argument{},
	)
	args, err := callFunc.Inputs.Unpack([]byte(txInputData[4:])) // first 4 bytes is func sig
	if err != nil {
		panic(err)
	}

	proof, err := decodeProof(args[1].([]byte))
	if err != nil {
		panic(err)
	}

	// Bytest1 is the inputs of exploit tx 0x05356fd06ce56a9ec5b4eaf9c075abd740cae4c21eab1676440ab5cd2fe5c57a
	bz, _ := json.MarshalIndent(proof, "", "\t")

	prt := lightclient.DefaultProofRuntime()
	poz, err := prt.DecodeProof(proof)
	if err != nil {
		panic(err)
	}
	// The length of normal proof ops is 1
	iavl := poz[0].(iavl2.IAVLValueOp)
	return string(bz), len(iavl.Proof.Leaves) != 1
}

func main() {
	proofData, _ := hex.DecodeString("0af9090a066961766c3a76120e00000100380200000000010fd9f61ade09dc090ad9090a2f081910c2a7c108189fbdb4860122206a972442231cdcbd083f53f5b6e7d1364d01a7c3e39481a393663421d9d91e730a2f081810f0e8c205189fbdb486012220015e9258171954de124eadca473471c85a218d1b4f30ab6046123df79b143e100a2f081710f0a8c302189fbdb486012220653ec3905c6eea07cd6122664c235a5bbee741796e9beb0090b651f1881aa6af0a2f081610f0a88401189fbdb48601222010da239ec014e3708bb63394a6ac659bf0a5775e01fb061ba47489f5a70a1e590a2e081510f0a854189fbdb48601222016d590ab6e451029d6e0fe2e414519bad0722c7960915b09709a8d79489e689f0a2e081410f0a824189fbdb48601222065097f751808e59d6614d0b73af9b86b2705572a494cb6000a022b11b2b430df0a2e081310f0a80c189fbdb486012220cc4a2ea4b5d72992127517bc895a92852ee43ee8020b14ad4e17ae86e9217e3d0a2e081210f0a806189fbdb486012a2006fb2e7115066cd11eaf2b0f9290409c8006d3c05bb02753a4a027e9b787baa80a2e081110f9b504189fbdb4860122209e9e95c585964204d71aeb79ca70d61f1de0587969d26508574d301baaffaa2e0a2e081010f9b502189fbdb486012220cd36752363a95efc2c7c389efa9be70939e1a5fe0ff8b6a4220e6f914b194b940a2e080f10f9b501189fbdb4860122209916492b300002424a1bf5bda681579fcb9cc6ec71bde2d5a9a2de07a021d6960a2d080e10f975189fbdb486012220475d2672afe6deadb2bfd11e9b5f3f39bfcc6bdf64886c40acd43aff0dd582120a2d080d10f935189fbdb4860122206ba10f6fa49cbeb0d188008d150ff4a0fcf41cc97bcf7747ab6872be4c2778ea0a2d080c10f915189fbdb4860122205ce365867ef1455e588031606b4b337145df37bfddf6c7286f0b57af3adc55b70a2d080b10f90d189fbdb486012220f26682bea502485550d7a18b737d63c73b29129eb6d795bfc0433a51d42d01910a2d080a10f905189fbdb486012220ebe3bb28c045dab1ae76e2fda3cab03c7de6561f907e1e3bc9591b724bf09fa60a2d080910f903189fbdb486012220510a14d4485acf2446aa6e35f7050bac3957614d66edac20e32f3854c35958280a2d080810f901189fbdb486012220dc916c09ce783c9f75c9087949d668fa45aea25177e0934c27d238cb6a5d212e0a2c08071079189fbdb486012220d0cc827b3d14741ae1feebbeeee281d857c369071703b9b047d961b640f0eed90a2c08061039189fbdb486012220d0898ff4c3490db572b9e0572766edbbd95ef8c111142a8ff55918118c75e79e0a2c08051019189fbdb4860122206d880990e45fc387e6c03e9e59a788fa6bec9e59cdb95f30f8c93dd5aac8c4790a2c08041009189fbdb486012220d3f0a14b73825683405f97c399e564e498163302275fd3541232cb15a4c4576a0a2c08031005189fbdb486012220c7f877f648d57282be001b932cda8123a41201969d0849018b9cd7b3384698230a2c08021003189fbdb486012220082eccf1e75741822f12b68807a405cc8eacef8ecda351dd6482084d65f40dd40a2c08011002189fbdb486012a2037ed9c4d68c5daf1733b2b1fa883584844b3cfed154ec484fe8c4af7f29455481a380a0e00000100380200000000010fd9f6122090a8172c037fb3e56a3b484787fcffbf48d016995f5c5ca435afd98f95475e0f1895bdb486010aa0060a0a6d756c746973746f726512036962631a8c068a060a87060a310a03646578122a0a2808a0bdb4860112204003f9e7b6a2140343f8a3a3af838083ec8612c80bc3c8de75f6ecdf1237c35e0a370a0974696d655f6c6f636b122a0a2808a0bdb48601122097a5368449ea8d71136144b9d5c9c6916c5960faaab04174a811c0f8fce7f4c00a0f0a0376616c12080a0608a0bdb486010a120a066f7261636c6512080a0608a0bdb486010a340a06746f6b656e73122a0a2808a0bdb4860112205eef37c05d0224d5f282d10789bb3ce89454bbd91d6e983cf1ccf9f1923bfc960a180a0c7374616b655f72657761726412080a0608a0bdb486010a390a0b61746f6d69635f73776170122a0a2808a0bdb48601122060ec555292e4766b5ee56e90b28c3697744befb37eff22a1f706a160f6a257d90a310a03616363122a0a2808a0bdb486011220446940460d26c196a5fa96ae18187cbf8dc435f1dd9e06be2fbaebdf07cd03800a310a03676f76122a0a2808a0bdb4860112208d7e73e28c1f0e7f36060cd8db2457d5071589d2b6d9eab9e1b1ad0ef4f57a780a300a027363122a0a2808a0bdb486011220997224d4cc646f90b3a5c95c3f29ac18c2d1c62d5db7086073ee337b8ff6ddbe0a360a08736c617368696e67122a0a2808a0bdb48601122096292ff1fb0e2020e14e2c6ae55a96b5b163ee58ec72af4085a3d82d2200031b0a310a03696263122a0a2808a0bdb4860112208894adad39e7e495f955e8b281b56e2492166313d835247b743ab91c15c483c90a100a046d61696e12080a0608a0bdb486010a330a057061697273122a0a2808a0bdb48601122095865a2eb97bdfe8e62765d8f0627a9f94ff56425c880a6900386e3a5e5355dd0a330a057374616b65122a0a2808a0bdb486011220d139a8cb1edd764d783d30d56081ab86a2ea02affa720751bcc19aaf5323d3700a340a06627269646765122a0a2808a0bdb4860112204792e8b647c9ef9d82e8fe0505ae8034b41b3bfd4d5ddc02ac90767586eace5b0a340a06706172616d73122a0a2808a0bdb48601122023c2f8353abab04889611cf1df2db289c433739a0b862982eb101d6bceddf8f4")
	if proof, err := decodeProof(proofData); err != nil {
		fmt.Printf("found attacking transaction %v \n", err)
	} else {
		prt := lightclient.DefaultProofRuntime()
		poz, err := prt.DecodeProof(proof)
		if err != nil {
			panic(err)
		}
		// The length of normal proof ops is 1
		iavl := poz[0].(iavl2.IAVLValueOp)
		abnormal := len(iavl.Proof.Leaves) != 1
		if abnormal {
			fmt.Println("This is an attack transaction with multi leaf node")
		} else {
			fmt.Println("This is a normal transaction")
		}
	}
}
