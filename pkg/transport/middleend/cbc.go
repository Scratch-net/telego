package middleend

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"slices"
)

const maxCBCPlaintextPerFeed = MaxMEFrameSize / aes.BlockSize * aes.BlockSize

// CBCEncrypter owns one continuous AES-256-CBC write state. It is not safe for
// concurrent use.
type CBCEncrypter struct {
	mode cipher.BlockMode
}

// String prevents accidental disclosure of expanded AES state.
func (CBCEncrypter) String() string {
	return "middleend.CBCEncrypter{redacted}"
}

// GoString prevents accidental disclosure of expanded AES state.
func (CBCEncrypter) GoString() string {
	return "middleend.CBCEncrypter{redacted}"
}

// NewCBCEncrypter creates a continuous Middle-End write cipher.
func NewCBCEncrypter(key []byte, iv []byte) (*CBCEncrypter, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("create middle-end CBC encrypter: key length %d, want 32", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create middle-end AES cipher: %w", err)
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("create middle-end CBC encrypter: IV length %d, want %d", len(iv), aes.BlockSize)
	}
	return &CBCEncrypter{mode: cipher.NewCBCEncrypter(block, iv)}, nil
}

// Encrypt encrypts one or more complete plaintext frames. When the frames do
// not end on a CBC block boundary, it appends repeated little-endian length-4
// no-op frames, matching tcp_rpc_flush in Telegram's net-tcp-rpc-common.c. A
// batch is limited to the same local plaintext budget as CBCDecrypter.Feed.
func (e *CBCEncrypter) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 || len(plaintext)%NoopFrameSize != 0 {
		return nil, fmt.Errorf("%w: length %d", ErrInvalidPlaintext, len(plaintext))
	}
	if len(plaintext) > maxCBCPlaintextPerFeed {
		return nil, fmt.Errorf("%w: length %d exceeds local batch maximum %d", ErrInvalidPlaintext, len(plaintext), maxCBCPlaintextPerFeed)
	}

	paddingSize := 0
	if remainder := len(plaintext) % aes.BlockSize; remainder != 0 {
		paddingSize = aes.BlockSize - remainder
	}
	if len(plaintext) > int(^uint(0)>>1)-paddingSize {
		return nil, fmt.Errorf("%w: padded length overflows int", ErrInvalidPlaintext)
	}
	paddedSize := len(plaintext) + paddingSize
	padded := make([]byte, len(plaintext), paddedSize)
	copy(padded, plaintext)
	for range paddingSize / NoopFrameSize {
		padded = binary.LittleEndian.AppendUint32(padded, NoopFrameSize)
	}

	e.mode.CryptBlocks(padded, padded)
	return padded, nil
}

// CBCDecrypter owns one continuous AES-256-CBC read state and buffers at most
// one incomplete ciphertext block. It is not safe for concurrent use.
type CBCDecrypter struct {
	mode    cipher.BlockMode
	pending []byte
}

// String prevents accidental disclosure of expanded AES and pending state.
func (CBCDecrypter) String() string {
	return "middleend.CBCDecrypter{redacted}"
}

// GoString prevents accidental disclosure of expanded AES and pending state.
func (CBCDecrypter) GoString() string {
	return "middleend.CBCDecrypter{redacted}"
}

// NewCBCDecrypter creates a continuous Middle-End read cipher.
func NewCBCDecrypter(key []byte, iv []byte) (*CBCDecrypter, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("create middle-end CBC decrypter: key length %d, want 32", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create middle-end AES cipher: %w", err)
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("create middle-end CBC decrypter: IV length %d, want %d", len(iv), aes.BlockSize)
	}
	return &CBCDecrypter{mode: cipher.NewCBCDecrypter(block, iv)}, nil
}

// Feed decrypts a bounded prefix of data and returns the bytes consumed. The
// caller must resume with data[consumed:] when a coalesced read exceeds the
// bounded output budget. Returned plaintext retains official no-op alignment
// frames for FrameDecoder to skip.
func (d *CBCDecrypter) Feed(data []byte) (int, []byte) {
	if len(data) == 0 {
		return 0, nil
	}

	if len(d.pending) == 0 {
		return d.feedAligned(data)
	}
	return d.feedWithPending(data)
}

func (d *CBCDecrypter) feedAligned(data []byte) (int, []byte) {
	completeSize := min(len(data)/aes.BlockSize*aes.BlockSize, maxCBCPlaintextPerFeed)
	if completeSize == 0 {
		d.pending = slices.Clone(data)
		return len(data), nil
	}

	plaintext := make([]byte, completeSize)
	d.mode.CryptBlocks(plaintext, data[:completeSize])
	consumed := completeSize
	remaining := data[completeSize:]
	if completeSize < maxCBCPlaintextPerFeed && len(remaining) < aes.BlockSize {
		d.pending = slices.Clone(remaining)
		consumed += len(remaining)
	}
	return consumed, plaintext
}

func (d *CBCDecrypter) feedWithPending(data []byte) (int, []byte) {
	needed := aes.BlockSize - len(d.pending)
	if len(data) < needed {
		d.pending = append(d.pending, data...)
		return len(data), nil
	}

	remaining := data[needed:]
	directSize := min(len(remaining)/aes.BlockSize*aes.BlockSize, maxCBCPlaintextPerFeed-aes.BlockSize)
	plaintext := make([]byte, aes.BlockSize+directSize)

	var firstBlock [aes.BlockSize]byte
	copy(firstBlock[:], d.pending)
	copy(firstBlock[len(d.pending):], data[:needed])
	d.mode.CryptBlocks(plaintext[:aes.BlockSize], firstBlock[:])
	clear(firstBlock[:])
	clear(d.pending)
	d.pending = nil

	if directSize != 0 {
		d.mode.CryptBlocks(plaintext[aes.BlockSize:], remaining[:directSize])
	}
	consumed := needed + directSize
	tail := remaining[directSize:]
	if len(plaintext) < maxCBCPlaintextPerFeed && len(tail) < aes.BlockSize {
		d.pending = slices.Clone(tail)
		consumed += len(tail)
	}
	return consumed, plaintext
}

// Finish reports a truncated AES-CBC block at end of stream.
func (d *CBCDecrypter) Finish() error {
	if len(d.pending) != 0 {
		return fmt.Errorf("%w: %d buffered bytes", ErrIncompleteBlock, len(d.pending))
	}
	return nil
}
