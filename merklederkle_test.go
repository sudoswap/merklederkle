package merklederkle

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
)

func TestMerkleTree_Root(t *testing.T) {
	leaves := []Bytes{
		{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
			0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
			0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
		{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
			0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
			0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
			0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40},
		{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
			0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
			0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
			0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60},
	}
	tree := MakeMerkleTree(leaves)
	fmt.Println(tree)
	fmt.Println("root: " + hex.EncodeToString(tree[0]))
	if hex.EncodeToString(tree[0]) != "bf7ba5aed55146169080251077c6b40043140706ee4a0e7365595803490104df" {
		t.Error("root is not correct")
	}
	index := 2
	proof, _ := GetProof(tree, index)
	fmt.Print("\nproof: ")
	fmt.Printf("%v\n", proof)

	leaf := leaves[index]
	root, _ := ProcessProof(leaf, proof)
	fmt.Println(root)
	fmt.Println(hex.EncodeToString(root))

	multiProof := GetMultiProof(tree, []int{index + 1})
	fmt.Println(multiProof)
	if hex.EncodeToString(multiProof.Leaves[0]) != "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40" {
		t.Errorf("leaf is not correct, %s vs actual %s", hex.EncodeToString(multiProof.Leaves[0]), "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40")
	}

	multiRoot := ProcessMultiProof(multiProof)
	fmt.Println(multiRoot)

	valid := isValidMerkleTree(tree)
	fmt.Println(valid)

	numbas := make([]*big.Int, 0)
	for _, l := range leaves {
		bigInt := new(big.Int)
		bigInt.SetBytes(l)
		numbas = append(numbas, bigInt)
	}
	newTree := GenerateMerkleTree(numbas)
	for _, bt := range newTree {
		fmt.Println("branch " + hex.EncodeToString(bt))
	}
}
