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
	"strings"
	"time"
)

type Cert struct { //自定义的证书格式
	Pubk  *ecdsa.PublicKey
	SysID []byte
	TxID  *big.Int
	rText *big.Int
	sText *big.Int
	TS    time.Time
}

type Msg struct {
	iCert Cert
	msg   string
	ts    time.Time
	rText *big.Int
	sText *big.Int
	hCode string
}

func SHA256Str(src string) string {
	h := sha256.New()
	h.Write([]byte(src))
	return hex.EncodeToString(h.Sum(nil))
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

func SignECC(msg []byte, path string) (*big.Int, *big.Int) {
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
	//rtext, _ := r.MarshalText()
	//stext, _ := s.MarshalText()
	//fmt.Println(r, s)
	return r, s
}

func verifyCert(iCert Cert) bool {
	h := sha256.New()
	h.Write(iCert.SysID)
	bytes := h.Sum(nil)
	vFlag := ecdsa.Verify(iCert.Pubk, bytes, iCert.rText, iCert.sText)
	return vFlag
}

func verifyMsgSig(mstr string, imsg Msg) bool {
	h := sha256.New()
	h.Write([]byte(mstr))
	bytes := h.Sum(nil)
	vFlag := ecdsa.Verify(imsg.iCert.Pubk, bytes, imsg.rText, imsg.sText)
	return vFlag
}

func generatemMsg(iCert Cert) Msg { //生成方案中合法的消息
	msg := "The road ahead is frozen for 100 meters"
	ts_g := time.Now()
	hcode := SHA256Str(msg)
	mStr := msg + ts_g.GoString() + hcode
	r, s := SignECC([]byte(mStr), "eccprivate-agent-A.pem")
	iMsg := Msg{iCert, msg, ts_g, r, s, hcode}
	return iMsg
}

func verifyMsg(imsg Msg) bool {
	ts_now := time.Now()
	//fmt.Println(ts_now.UnixMicro() - imsg.ts.UnixMicro())
	if ts_now.UnixMicro()-imsg.ts.UnixMicro() > 30000 {
		return false //时效性验证
	}
	// 验证证书的合法性
	flag := verifyCert(imsg.iCert)
	if flag == false {
		return false
	}
	hcode := SHA256Str(imsg.msg)
	if strings.Compare(hcode, imsg.hCode) != 0 {
		return false
	}
	mStr := imsg.msg + imsg.ts.GoString() + imsg.hCode
	flag = verifyMsgSig(mStr, imsg)
	if flag == false {
		return false
	}
	return true
}

func main() {
	iCert := generateCert()
	//fmt.Println(iCert)
	iMsg := generatemMsg(iCert)

	starttime := time.Now()
	for i := 0; i < 10; i++ {
		flag := verifyMsg(iMsg)
		if flag {
			fmt.Println("msg  verify is ok")
		} else {
			fmt.Println("msg verify is error")
		}
	}
	elapsed := time.Since(starttime)
	fmt.Println("App elapsed: ", elapsed)

}
