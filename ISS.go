package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

type Cert struct {
	Pubk  *ecdsa.PublicKey
	SysID []byte
	TxID  *big.Int
	rText []byte
	sText []byte
	TS    time.Time
}

func generateRID() *big.Int {
	big1 := new(big.Int).SetUint64(uint64(1000))
	RID, err := rand.Int(rand.Reader, big1)
	if err != nil {
		fmt.Print(err)
	}
	//fmt.Println(RID)
	return RID
}

func SHA256Str(src string) string {
	h := sha256.New()
	h.Write([]byte(src))
	return hex.EncodeToString(h.Sum(nil))
}

func generateECCKey() {
	fmt.Println("GenerateECCKey Starting")
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	//x509编码
	eccPrivateKey, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		panic(err)
	}
	//pem编码
	privateBlock := pem.Block{
		Type:  "ecc private key",
		Bytes: eccPrivateKey,
	}
	//保存私钥
	privatefile, err := os.Create("eccprivate-agent-A.pem")
	if err != nil {
		panic(err)
	}
	pem.Encode(privatefile, &privateBlock) //Encode：把字节数组编码成PEM格式的文件。
	publicKey := privateKey.PublicKey
	eccPublicKey, err := x509.MarshalPKIXPublicKey(&publicKey)
	publicBlock := pem.Block{
		Type:  "ecc public key",
		Bytes: eccPublicKey,
	}
	publicfile, err := os.Create("eccpublic-agent-A.pem")
	if err != nil {
		panic(err)
	}
	pem.Encode(publicfile, &publicBlock)

	fmt.Println("GenerateECCKey Finishing")
}

func getECCPublicKey(path string) *ecdsa.PublicKey {
	file, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	info, _ := file.Stat()
	buf := make([]byte, info.Size())
	file.Read(buf)
	//pem解码
	block, _ := pem.Decode(buf)
	//x509解密
	publicInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	publicKey := publicInterface.(*ecdsa.PublicKey)
	return publicKey
}

func GetECCPrivateKey(path string) *ecdsa.PrivateKey {
	file, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	info, _ := file.Stat()
	buf := make([]byte, info.Size())
	file.Read(buf)
	//pem解码
	block, _ := pem.Decode(buf)
	//x509解码
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	return privateKey
}

func SignECC(msg []byte, path string) ([]byte, []byte) {
	//取得私钥
	privateKey := GetECCPrivateKey(path)
	//计算哈希值
	hash := sha256.New()
	//填入数据
	hash.Write(msg)
	bytes := hash.Sum(nil)
	//对哈希值生成数字签名
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, bytes)
	if err != nil {
		panic(err)
	}
	rtext, _ := r.MarshalText()
	stext, _ := s.MarshalText()
	//fmt.Println(r, s)
	return rtext, stext
}

func generateCert() Cert {
	var myCert Cert
	Pubk := getECCPublicKey("eccpublic-agent-A.pem")
	myCert.Pubk = Pubk
	rid := generateRID()
	hash := sha256.New()
	ts := time.Now()

	SysId := rid.String() + ts.GoString()
	bytes := hash.Sum([]byte(SysId))
	myCert.SysID = bytes
	myCert.TS = time.Now()

	rText, sText := SignECC(myCert.SysID, "eccprivate-agent-A.pem")

	big1 := new(big.Int).SetUint64(uint64(3000))
	TID, _ := rand.Int(rand.Reader, big1)
	myCert.TxID = TID
	myCert.rText = rText
	myCert.sText = sText
	return myCert
}

func issuedSC(myCert Cert, myLedger map[*ecdsa.PublicKey]bool) bool {
	_, ok := myLedger[myCert.Pubk]
	if ok {
		fmt.Println("The certificate has been issued")
	} else {
		myLedger[myCert.Pubk] = true
		return true
	}
	return false
}

func main() {
	fmt.Println("Hello World!")
	var issuedLedger map[*ecdsa.PublicKey]bool //账本的模拟容器
	issuedLedger = make(map[*ecdsa.PublicKey]bool)
	myCert := generateCert()

	starttime := time.Now()
	for i := 0; i < 10; i++ {
		flag := issuedSC(myCert, issuedLedger)
		if flag == true {
			fmt.Println("Set Certificate Ok!")
		} else {
			fmt.Println("Set Certificate failed!")
		}
	}
	elapsed := time.Since(starttime)
	fmt.Println("App elapsed: ", elapsed)

}
