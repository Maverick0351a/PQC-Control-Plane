package merkle

// Minimal append-only Merkle tree (not persisted) placeholder.

import (
	"crypto/sha256"
)

type Tree struct { Leaves [][]byte }

func New() *Tree { return &Tree{Leaves: [][]byte{}} }

func (t *Tree) Append(leaf []byte) []byte {
	// store leaf hash
	h := sha256.Sum256(leaf)
	clone := make([]byte, 32)
	copy(clone, h[:])
	t.Leaves = append(t.Leaves, clone)
	return clone
}

func (t *Tree) Root() []byte {
	if len(t.Leaves) == 0 { return nil }
	layer := t.Leaves
	for len(layer) > 1 {
		next := [][]byte{}
		for i := 0; i < len(layer); i += 2 {
			if i+1 == len(layer) {
				next = append(next, layer[i])
				break
			}
			concat := append(append([]byte{}, layer[i]...), layer[i+1]...)
			h := sha256.Sum256(concat)
			next = append(next, h[:])
		}
		layer = next
	}
	return layer[0]
}
