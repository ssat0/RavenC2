package obfuscator

import (
	// crypto/rand for alias
	"encoding/hex"
	"math"
	"math/rand" // math/rand added
	"runtime"
	"strings"
	"time"
	"unsafe"
)

// Junk functions
func calculatePi() float64 {
	pi := 3.14159
	for i := 0; i < 1000; i++ {
		pi += math.Sin(float64(i)) / math.Cos(float64(i))
		pi -= math.Tan(float64(i))
	}
	return pi
}

func generateRandomString() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

type RuntimeObfuscator struct {
	junkData     []byte
	originalCode []byte
}

func New() *RuntimeObfuscator {
	return &RuntimeObfuscator{
		junkData: make([]byte, 1024*1024), // 1MB junk data for obfuscation
	}
}

func (r *RuntimeObfuscator) Obfuscate(code []byte) []byte {
	// Junk operations
	go func() {
		for {
			calculatePi()
			generateRandomString()
			time.Sleep(100 * time.Millisecond)
		}
	}()

	// Memory layout obfuscation
	rand.Read(r.junkData)
	runtime.GC()

	// String obfuscation
	obfuscated := make([]byte, len(code))
	key := byte(time.Now().UnixNano())

	for i := 0; i < len(code); i++ {
		// XOR encryption with random padding
		obfuscated[i] = code[i] ^ key ^ r.junkData[i%len(r.junkData)]
	}

	// Memory obfuscation
	r.memoryObfuscation()

	return obfuscated
}

func (r *RuntimeObfuscator) memoryObfuscation() {
	// Heap obfuscation
	data := make([][]byte, 100)
	for i := 0; i < 100; i++ {
		data[i] = make([]byte, 1024)
		rand.Read(data[i])
	}

	// Stack obfuscation
	var stackData [1024]byte
	for i := range stackData {
		stackData[i] = byte(rand.Int31())
	}

	// Pointer manipulation
	ptr := unsafe.Pointer(&stackData)
	for i := 0; i < 1000; i++ {
		*(*byte)(unsafe.Pointer(uintptr(ptr) + uintptr(i%1024))) ^= byte(i)
	}
}

func (r *RuntimeObfuscator) AddJunkCode() {
	// Useless operations
	go func() {
		matrix := make([][]int, 100)
		for i := range matrix {
			matrix[i] = make([]int, 100)
			for j := range matrix[i] {
				matrix[i][j] = i * j
			}
		}
	}()

	// Fake network activity
	go func() {
		fakeData := strings.Repeat("JUNK", 1000)
		for {
			_ = len(fakeData) * 2
			time.Sleep(50 * time.Millisecond)
		}
	}()

	// CPU load
	go func() {
		for {
			x := 0.0
			for i := 0; i < 1000; i++ {
				x += math.Sqrt(float64(i))
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
}
