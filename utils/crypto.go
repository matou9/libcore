package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/denisbrodbeck/machineid"
	"log"
	"math/rand"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
)

type DecryptResult struct {
	Data interface{}
	Raw  []byte
}

type cryptoImpl struct {
	key           []byte
	gcm           cipher.AEAD
	refCount      int32
	destroyed     int32
	finalizerDone chan struct{}
}

var (
	instance *cryptoImpl
	once     sync.Once
	mu       sync.RWMutex
	wg       sync.WaitGroup
)

func New(key []byte) (*cryptoImpl, error) {
	if len(key) != 32 {
		machineId, err := machineid.ID()
		machineId = "d0445245-8cd6-43de-9453-21ededd14c3e"
		if err != nil {
			key = []byte("vpn_2025vpn_2025vpn_2025vpn_2025")
		} else {
			hash := sha256.Sum256([]byte(machineId))
			key = hash[:]
		}
	}

	once.Do(func() {
		instance = &cryptoImpl{
			key:           append([]byte(nil), key...),
			refCount:      0,
			finalizerDone: make(chan struct{}),
		}

		block, err := aes.NewCipher(instance.key)
		if err != nil {
			log.Fatalf("failed to create cipher: %v", err)
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			log.Fatalf("failed to create GCM: %v", err)
		}
		instance.gcm = gcm

		runtime.SetFinalizer(instance, finalizer)
	})

	if atomic.LoadInt32(&instance.destroyed) == 1 {
		return nil, ErrInstanceDestroyed
	}

	atomic.AddInt32(&instance.refCount, 1)
	return instance, nil
}

func finalizer(c *cryptoImpl) {
	if c != nil && c.finalizerDone != nil {
		select {
		case <-c.finalizerDone:
		default:
			close(c.finalizerDone)
		}
	}
	c.Destroy()
}

func (c *cryptoImpl) Encrypt(data interface{}) (string, error) {
	if atomic.LoadInt32(&c.destroyed) == 1 {
		return "", ErrInstanceDestroyed
	}

	wg.Add(1)
	defer wg.Done()

	mu.RLock()
	defer mu.RUnlock()

	// 处理不同类型的输入
	var plaintext []byte
	var err error

	switch v := data.(type) {
	case string:
		plaintext = []byte(v)
	case []byte:
		plaintext = v
	default:
		plaintext, err = json.Marshal(data)
		if err != nil {
			return "", err
		}
	}

	nonce := make([]byte, c.gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	ciphertext := c.gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (c *cryptoImpl) Decrypt(encrypted string) (*DecryptResult, error) {
	if atomic.LoadInt32(&c.destroyed) == 1 {
		return nil, ErrInstanceDestroyed
	}

	wg.Add(1)
	defer wg.Done()

	mu.RLock()
	defer mu.RUnlock()

	data, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return nil, err
	}

	nonceSize := c.gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, ErrInvalidData
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := c.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	// 尝试作为 JSON 解析
	var result interface{}
	if err := json.Unmarshal(plaintext, &result); err != nil {
		// JSON 解析失败，返回原始数据
		return &DecryptResult{
			Data: string(plaintext),
			Raw:  plaintext,
		}, nil
	}

	return &DecryptResult{
		Data: result,
		Raw:  plaintext,
	}, nil
}

func (c *cryptoImpl) LoadFromFile(filename string) (*DecryptResult, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	if !c.IsEncrypted(data) {
		// 非加密数据，返回原始内容
		return &DecryptResult{
			Data: string(data),
			Raw:  data,
		}, nil
	}

	return c.Decrypt(string(data))
}

func (c *cryptoImpl) SaveToFile(data interface{}, filename string) error {
	encrypted, err := c.Encrypt(data)
	if err != nil {
		return fmt.Errorf("加密失败: %w", err)
	}
	// 将加密后的密文写入文件
	return os.WriteFile(filename, []byte(encrypted), 0644)
}

func (c *cryptoImpl) IsEncrypted(data []byte) bool {
	_, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return false
	}

	if json.Valid(data) {
		return false
	}

	return true
}

func (c *cryptoImpl) Destroy() {
	if c == nil {
		return
	}

	if atomic.LoadInt32(&c.destroyed) == 1 {
		return
	}

	if atomic.AddInt32(&c.refCount, -1) > 0 {
		return
	}

	mu.Lock()
	defer mu.Unlock()

	wg.Wait()

	atomic.StoreInt32(&c.destroyed, 1)

	for i := range c.key {
		c.key[i] = 0
	}
	c.key = nil
	c.gcm = nil

	instance = nil
	once = sync.Once{}

	if c.finalizerDone != nil {
		select {
		case <-c.finalizerDone:
		default:
			close(c.finalizerDone)
		}
	}
}

func LoadFromFile(filename string) (*DecryptResult, error) {
	crypto, err := New(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create crypto instance: %w", err)
	}
	defer crypto.Destroy()

	return crypto.LoadFromFile(filename)
}

func SaveToFile(data interface{}, filename string) error {
	crypto, err := New(nil)
	if err != nil {
		return fmt.Errorf("failed to create crypto instance: %w", err)
	}
	defer crypto.Destroy()

	return crypto.SaveToFile(data, filename)
}

var (
	ErrInvalidKeyLength  = errors.New("invalid key length")
	ErrInstanceDestroyed = errors.New("instance has been destroyed")
	ErrInvalidData       = errors.New("invalid encrypted data")
)
