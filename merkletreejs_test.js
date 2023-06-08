const { MerkleTree } = require('merkletreejs')
const { BigNumber } = require("@ethersproject/bignumber");
const { keccak256 } = require("@ethersproject/keccak256");

const hashFn = (tokenId) =>
    keccak256(Buffer.from(BigNumber.from(tokenId).toHexString().slice(2).padStart(64, "0"), "hex"));

const generateMerkleTree = (tokenIds) => {
    if (!tokenIds.length) {
        throw new Error("Could not generate merkle tree");
    }

    const leaves = tokenIds.map(hashFn);
    return new MerkleTree(leaves, keccak256, { sort: true });
};

const generateMerkleProof = (merkleTree, tokenId) =>
    merkleTree.getHexProof(hashFn(tokenId));

const leavesArr = [
    Uint8Array.from([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ]),
    Uint8Array.from([
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
    ]),
    Uint8Array.from([
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
        0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
        0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60,
    ]),
];

const leaves = leavesArr.map(x => hashFn(x))
const tree = new MerkleTree(leaves, hashFn)
console.log(tree.getHexLeaves())
console.log(tree.toString())
const root = tree.getRoot().toString('hex')
const leaf = hashFn(leavesArr[0])
const proof = tree.getProof(leaf)
console.log(tree.verify(proof, leaf, root)) // true

const newTree = generateMerkleTree(leavesArr)
console.log(newTree.getHexLeaves())
console.log(newTree.toString())
const root2 = newTree.getRoot().toString('hex')
const leaf2 = hashFn(leavesArr[0])
const proof2 = newTree.getProof(leaf2)
console.log(tree.verify(proof2, leaf2, root2)) // true
