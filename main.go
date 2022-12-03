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
	proofData := common.FromHex("0x0a8d020a066961766c3a76120e00000100380200000000010dd9ac1af201f0010aed010a2b0802100318b091c73422200c10f902d266c238a4ca9e26fa9bc36483cd3ebee4e263012f5e7f40c22ee4d20a4d0801100218b091c7342220e4fd47bffd1c06e67edad92b2bf9ca63631978676288a2aa99f95c459436ef632a20121a1f9c4eca726c725796c5375fc4158986ced08e498dc8268ef94d8ed1891612001a370a0e0000010038020000000000000002122011056c6919f02d966991c10721684a8d1542e44003f9ffb47032c18995d4ac7f18b091c7341a340a0e00000100380200000000010dd9ac12202c3a561458f8527b002b5ec3cab2d308662798d6245d4588a4e6a80ebdfe30ac18010ad4050a0a6d756c746973746f726512036962631ac005be050abb050a110a066f7261636c6512070a0508b891c7340a0f0a046d61696e12070a0508b891c7340a350a08736c617368696e6712290a2708b891c7341220c8ccf341e6e695e7e1cb0ce4bf347eea0cc16947d8b4e934ec400b57c59d6f860a380a0b61746f6d69635f7377617012290a2708b891c734122042d4ecc9468f71a70288a95d46564bfcaf2c9f811051dcc5593dbef152976b010a110a0662726964676512070a0508b891c7340a300a0364657812290a2708b891c73412201773be443c27f61075cecdc050ce22eb4990c54679089e90afdc4e0e88182a230a2f0a02736312290a2708b891c7341220df7a0484b7244f76861b1642cfb7a61d923794bd2e076c8dbd05fc4ee29f3a670a330a06746f6b656e7312290a2708b891c734122064958c2f76fec1fa5d1828296e51264c259fa264f499724795a740f48fc4731b0a320a057374616b6512290a2708b891c734122015d2c302143bdf029d58fe381cc3b54cedf77ecb8834dfc5dc3e1555d68f19ab0a330a06706172616d7312290a2708b891c734122050abddcb7c115123a5a4247613ab39e6ba935a3d4f4b9123c4fedfa0895c040a0a300a0361636312290a2708b891c734122079fb5aecc4a9b87e56231103affa5e515a1bdf3d0366490a73e087980b7f1f260a0e0a0376616c12070a0508b891c7340a300a0369626312290a2708b891c7341220e09159530585455058cf1785f411ea44230f39334e6e0f6a3c54dbf069df2b620a300a03676f7612290a2708b891c7341220db85ddd37470983b14186e975a175dfb0bf301b43de685ced0aef18d28b4e0420a320a05706169727312290a2708b891c7341220a78b556bc9e73d86b4c63ceaf146db71b12ac80e4c10dd0ce6eb09c99b0c7cfe0a360a0974696d655f6c6f636b12290a2708b891c73412204775dbe01d41cab018c21ba5c2af94720e4d7119baf693670e70a40ba2a52143")
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
