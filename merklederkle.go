package merklederkle

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"math"
	"math/big"
	"sort"
)

type Bytes []byte

func (b *Bytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(*b))
}

func (b *Bytes) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	decoded, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	*b = decoded
	return nil
}

func keccak256(data ...[]byte) Bytes {
	hash := crypto.Keccak256(data...)
	return Bytes(hash)
}

func concatBytes(data ...Bytes) Bytes {
	result := make(Bytes, 0)
	for _, d := range data {
		result = append(result, d...)
	}
	return result
}

func equalsBytes(a Bytes, b Bytes) bool {
	return bytesEqual(a, b)
}

func bytesEqual(a Bytes, b Bytes) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func throwError(msg string) error {
	return errors.New(msg)
}

func hashPair(a Bytes, b Bytes) Bytes {
	if bytes.Compare(a, b) > 0 {
		a, b = b, a
	}
	return keccak256(concatBytes(a, b))
}

func leftChildIndex(i int) int {
	return 2*i + 1
}

func rightChildIndex(i int) int {
	return 2*i + 2
}

func parentIndex(i int) (int, error) {
	if i > 0 {
		return (i - 1) / 2, nil
	}
	return 0, throwError("Root has no parent")
}

func siblingIndex(i int) int {
	if i > 0 {
		return i - int(math.Pow(-1, float64(i%2)))
	}
	throwError("Root has no siblings")
	return 0
}

func isTreeNode(tree []Bytes, i int) bool {
	return i >= 0 && i < len(tree)
}

func isInternalNode(tree []Bytes, i int) bool {
	return isTreeNode(tree, leftChildIndex(i))
}

func isLeafNode(tree []Bytes, i int) bool {
	return isTreeNode(tree, i) && !isInternalNode(tree, i)
}

func isValidMerkleNode(node Bytes) bool {
	return len(node) == 32
}

func checkLeafNode(tree []Bytes, i int) error {
	if !isLeafNode(tree, i) {
		return throwError("Index is not a leaf")
	}
	return nil
}

func checkValidMerkleNode(node Bytes) error {
	if !isValidMerkleNode(node) {
		return throwError("Merkle tree nodes must be Bytes of length 32")
	}
	return nil
}

func MakeMerkleTree(leaves []Bytes) []Bytes {
	for _, leaf := range leaves {
		checkValidMerkleNode(leaf)
	}

	if len(leaves) == 0 {
		panic(errors.New("Expected non-zero number of leaves"))
	}
	sort.Slice(leaves, func(i, j int) bool { return bytes.Compare(leaves[i], leaves[j]) < 0 })
	tree := make([]Bytes, 2*len(leaves)-1)

	for i, leaf := range leaves {
		tree[len(tree)-1-i] = leaf
	}
	for i := len(tree) - 1 - len(leaves); i >= 0; i-- {
		tree[i] = hashPair(
			tree[leftChildIndex(i)],
			tree[rightChildIndex(i)],
		)
	}

	return tree
}

func GetProof(tree []Bytes, index int) ([]Bytes, error) {
	if err := checkLeafNode(tree, index); err != nil {
		return []Bytes{}, err
	}

	proof := make([]Bytes, 0)
	for index > 0 {
		proof = append(proof, tree[siblingIndex(index)])
		index, _ = parentIndex(index)
	}
	return proof, nil
}

func ProcessProof(leaf Bytes, proof []Bytes) (Bytes, error) {
	if err := checkValidMerkleNode(leaf); err != nil {
		return Bytes{}, err
	}
	for _, p := range proof {
		if err := checkValidMerkleNode(p); err != nil {
			return Bytes{}, err
		}
	}

	result := leaf
	for _, p := range proof {
		result = hashPair(result, p)
	}
	return result, nil
}

type MultiProof struct {
	Leaves     []Bytes
	Proof      []Bytes
	ProofFlags []bool
}

func GetMultiProof(tree []Bytes, indices []int) MultiProof {
	for _, i := range indices {
		checkLeafNode(tree, i)
	}
	indices = sortIndicesDesc(indices)

	if hasDuplicateIndex(indices) {
		panic(errors.New("Cannot prove duplicated index"))
	}

	stack := make([]int, len(indices))
	copy(stack, indices)
	proof := make([]Bytes, 0)
	proofFlags := make([]bool, 0)

	for len(stack) > 0 && stack[0] > 0 {
		j := stack[0]
		if len(stack) > 1 {
			stack = stack[1:] // consume from the stack
		} else {
			stack = make([]int, 0)
		}
		s := siblingIndex(j)
		p, _ := parentIndex(j)

		if len(stack) > 0 && s == stack[0] {
			proofFlags = append(proofFlags, true)
			if len(stack) > 1 {
				stack = stack[1:] // consume from the stack
			} else {
				stack = make([]int, 0)
			}
		} else {
			proofFlags = append(proofFlags, false)
			proof = append(proof, tree[s])
		}
		stack = append(stack, p)
	}

	if len(indices) == 0 {
		proof = append(proof, tree[0])
	}

	return MultiProof{
		Leaves:     getIndicesValues(tree, indices),
		Proof:      proof,
		ProofFlags: proofFlags,
	}
}

func ProcessMultiProof(multiproof MultiProof) Bytes {
	for _, l := range multiproof.Leaves {
		checkValidMerkleNode(l)
	}
	for _, p := range multiproof.Proof {
		checkValidMerkleNode(p)
	}

	if len(multiproof.Proof) < countFalse(multiproof.ProofFlags) {
		panic(errors.New("Invalid multiproof format"))
	}

	if len(multiproof.Leaves)+len(multiproof.Proof) != len(multiproof.ProofFlags)+1 {
		panic(errors.New("Provided leaves and multiproof are not compatible"))
	}

	stack := make([]Bytes, len(multiproof.Leaves))
	copy(stack, multiproof.Leaves)
	proof := make([]Bytes, len(multiproof.Proof))
	copy(proof, multiproof.Proof)

	for _, flag := range multiproof.ProofFlags {
		a := stack[0]
		if len(stack) > 1 {
			stack = stack[1:] // consume from the stack
		} else {
			stack = make([]Bytes, 0)
		}
		var b Bytes
		if flag {
			b = stack[0]
			if len(stack) > 1 {
				stack = stack[1:] // consume from the stack
			} else {
				stack = make([]Bytes, 0)
			}
		} else {
			b = proof[0]
			if len(proof) > 1 {
				proof = proof[1:] // consume from the stack
			} else {
				proof = make([]Bytes, 0)
			}
		}
		stack = append(stack, hashPair(a, b))
	}
	var result Bytes
	if len(stack) > 0 {
		result = stack[len(stack)-1]
	} else if len(proof) > 0 {
		result = proof[0]
	}
	return result
}

func isValidMerkleTree(tree []Bytes) bool {
	for i, node := range tree {
		if !isValidMerkleNode(node) {
			return false
		}

		l := leftChildIndex(i)
		r := rightChildIndex(i)

		if r >= len(tree) {
			if l < len(tree) {
				return false
			}
		} else if !equalsBytes(node, hashPair(tree[l], tree[r])) {
			return false
		}
	}

	return len(tree) > 0
}

func sortIndicesDesc(indices []int) []int {
	sortedIndices := make([]int, len(indices))
	copy(sortedIndices, indices)
	sort.Slice(sortedIndices, func(i, j int) bool {
		return sortedIndices[i] > sortedIndices[j]
	})
	return sortedIndices
}

func hasDuplicateIndex(indices []int) bool {
	seen := make(map[int]bool)
	for _, i := range indices {
		if seen[i] {
			return true
		}
		seen[i] = true
	}
	return false
}

func getIndicesValues(tree []Bytes, indices []int) []Bytes {
	values := make([]Bytes, len(indices))
	for i, index := range indices {
		values[i] = tree[index]
	}
	return values
}

func countFalse(flags []bool) int {
	count := 0
	for _, flag := range flags {
		if !flag {
			count++
		}
	}
	return count
}

/*
Go implementation of this typescript below this line:
import { BigNumber, BigNumberish } from "@ethersproject/bignumber";
import { keccak256 } from "@ethersproject/keccak256";
import MerkleTree from "merkletreejs";

export const hashFn = (tokenId: BigNumberish) =>
  keccak256(Buffer.from(BigNumber.from(tokenId).toHexString().slice(2).padStart(64, "0"), "hex"));

export const generateMerkleTree = (tokenIds: BigNumberish[]) => {
  if (!tokenIds.length) {
    throw new Error("Could not generate merkle tree");
  }

  const leaves = tokenIds.map(hashFn);
  return new MerkleTree(leaves, keccak256, { sort: true });
};

export const generateMerkleProof = (merkleTree: MerkleTree, tokenId: BigNumberish) =>
  merkleTree.getHexProof(hashFn(tokenId));
*/

func HashFn(tokenId *big.Int) Bytes {
	tokenIdBytes := tokenId.Bytes()
	paddedBytes := common.LeftPadBytes(tokenIdBytes, 32)
	return crypto.Keccak256(paddedBytes)
}

func GenerateMerkleTree(tokenIds []*big.Int) []Bytes {
	if len(tokenIds) == 0 {
		panic(errors.New("Could not generate merkle tree"))
	}

	leaves := make([]Bytes, len(tokenIds))
	for i, tokenId := range tokenIds {
		leaves[i] = HashFn(tokenId)
	}
	return MakeMerkleTree(leaves)
}

func GenerateMerkleProof(tree []Bytes, tokenId *big.Int) ([]Bytes, error) {
	leaf := HashFn(tokenId)
	index := -1
	for i, v := range tree {
		if bytesEqual(v, leaf) {
			index = i
			break
		}
	}
	if index == -1 {
		return nil, errors.New("Leaf not found in tree")
	}
	proof, err := GetProof(tree, index)
	if err != nil {
		return nil, err
	}
	return proof, nil
}

func GenerateMultiProof(tree []Bytes, tokenIds []*big.Int) (MultiProof, error) {
	indices := make([]int, len(tokenIds))
	for i, tokenId := range tokenIds {
		leaf := HashFn(tokenId)
		index := -1
		for j, v := range tree {
			if bytesEqual(v, leaf) {
				index = j
				break
			}
		}
		if index == -1 {
			return MultiProof{}, fmt.Errorf("Leaf for token ID %d not found in tree", tokenId)
		}
		indices[i] = index
	}
	multiproof := GetMultiProof(tree, indices)
	return multiproof, nil
}
