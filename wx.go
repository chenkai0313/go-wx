package go_wx

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"github.com/iGoogle-ink/gotil"
	xaes "github.com/iGoogle-ink/gotil/aes"
	"github.com/iGoogle-ink/gotil/xhttp"
	"hash"
	"io/ioutil"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

const (
	// 签名方式
	SignType_MD5         = "MD5"
	SignType_HMAC_SHA256 = "HMAC-SHA256"
)

type wxApp struct {
	AppId       string //小程序 appId
	AppSecret   string //小程序 appSecret
	PayMchid    string //商户号
	PayApikey   string //可在微信商户后台生成支付秘钥
	certificate tls.Certificate
	certPool    *x509.CertPool
}

func (w *wxApp) Transfer(req TransferReq) (res TransferRes, err error) {
	var result TransferRes
	reqUrl := "https://api.mch.weixin.qq.com/mmpaymkttransfers/promotion/transfers"
	type requestStruct struct {
		MchAppid       string `xml:"mch_appid" json:"mch_appid"`
		Mchid          string `xml:"mchid" json:"mchid"`
		NonceStr       string `xml:"nonce_str" json:"nonce_str"`
		PartnerTradeNo string `xml:"partner_trade_no" json:"partner_trade_no"`
		Openid         string `xml:"openid" json:"openid"`
		Amount         int64  `xml:"amount" json:"amount"`
		Desc           string `xml:"desc" json:"desc"`
		Sign           string `xml:"sign" json:"sign"`
		CheckName      string `xml:"check_name" json:"check_name"`
	}
	request := requestStruct{
		MchAppid:       w.AppId,
		Mchid:          w.PayMchid,
		NonceStr:       req.NonceStr,
		PartnerTradeNo: req.PartnerTradeNo,
		Openid:         req.Openid,
		Amount:         req.Amount,
		Desc:           req.Desc,
		CheckName:      "NO_CHECK",
	}
	requestMapSign := map[string]interface{}{
		"mch_appid":        w.AppId,
		"mchid":            w.PayMchid,
		"nonce_str":        req.NonceStr,
		"partner_trade_no": req.PartnerTradeNo,
		"openid":           req.Openid,
		"amount":           req.Amount,
		"desc":             req.Desc,
		"check_name":       "NO_CHECK",
	}
	sign := w.makeSign(requestMapSign, SignType_MD5, w.PayApikey)
	request.Sign = sign
	var (
		tlsConfig *tls.Config
		bs        []byte
	)
	if tlsConfig, err = w.addCertConfig(req.CertFilePath, req.KeyFilePath, req.Pkcs12FilePath); err != nil {
		return result, err
	}
	httpClient := xhttp.NewClient()
	requestMapStr, err := xml.Marshal(request)
	if err != nil {
		return result, err
	}
	httpClient.SetTLSConfig(tlsConfig)
	responseBody, bs, errs := httpClient.Type(xhttp.TypeXML).Post(reqUrl).SendString(string(requestMapStr[:])).EndBytes()
	if len(errs) > 0 {
		return result, errs[0]
	}
	if responseBody.StatusCode != 200 {
		return result, errors.New(fmt.Sprintf("HTTP Request Error, StatusCode = %d", responseBody.StatusCode))
	}
	//判断是否请求异常出错(返回的是html)
	if strings.Contains(string(bs), "HTML") || strings.Contains(string(bs), "html") {
		return result, errors.New(string(bs))
	}
	if err = xml.Unmarshal(bs, &result); err != nil {
		return result, fmt.Errorf("xml.Unmarshal(%s)：%w", string(bs), err)
	}
	return result, nil
}

func (w *wxApp) Refund(req RefundReq) (res RefundRes, err error) {
	var result RefundRes
	reqUrl := "https://api.mch.weixin.qq.com/secapi/pay/refund"
	type requestMapStruct struct {
		Appid       string `xml:"appid"`
		MchId       string `xml:"mch_id"`
		NonceStr    string `xml:"nonce_str"`
		OutTradeNo  string `xml:"out_trade_no"`
		OutRefundNo string `xml:"out_refund_no"`
		TotalFee    int64  `xml:"total_fee"`
		RefundFee   int64  `xml:"refund_fee"`
		Sign        string `xml:"sign"`
		NotifyUrl   string `xml:"notify_url"`
	}
	requestMap := requestMapStruct{
		Appid:       w.AppId,
		MchId:       w.PayMchid,
		NonceStr:    req.NonceStr,
		OutTradeNo:  req.OutTradeNo,
		OutRefundNo: req.OutRefundNo,
		TotalFee:    req.TotalFee,
		RefundFee:   req.RefundFee,
		NotifyUrl:   req.NotifyUrl,
	}
	requestMapSign := map[string]interface{}{
		"appid":         w.AppId,
		"mch_id":        w.PayMchid,
		"nonce_str":     req.NonceStr,
		"out_trade_no":  req.OutTradeNo,
		"out_refund_no": req.OutRefundNo,
		"total_fee":     req.TotalFee,
		"refund_fee":    req.RefundFee,
		"notify_url":    req.NotifyUrl,
	}
	var (
		bs        []byte
		tlsConfig *tls.Config
	)
	if tlsConfig, err = w.addCertConfig(req.CertFilePath, req.KeyFilePath, req.Pkcs12FilePath); err != nil {
		return result, err
	}
	sign := w.makeSign(requestMapSign, SignType_MD5, w.PayApikey)
	requestMap.Sign = sign
	httpClient := xhttp.NewClient()
	requestMapStr, err := xml.Marshal(requestMap)
	if err != nil {
		return result, err
	}
	httpClient.SetTLSConfig(tlsConfig)
	responseBody, bs, errs := httpClient.Type(xhttp.TypeXML).Post(reqUrl).SendString(string(requestMapStr[:])).EndBytes()
	if len(errs) > 0 {
		return result, errs[0]
	}
	if responseBody.StatusCode != 200 {
		return result, errors.New(fmt.Sprintf("HTTP Request Error, StatusCode = %d", responseBody.StatusCode))
	}
	//判断是否请求异常出错(返回的是html)
	if strings.Contains(string(bs), "HTML") || strings.Contains(string(bs), "html") {
		return result, errors.New(string(bs))
	}
	if err = xml.Unmarshal(bs, &result); err != nil {
		return result, fmt.Errorf("xml.Unmarshal(%s)：%w", string(bs), err)
	}
	return result, nil
}

func (w *wxApp) addCertConfig(certFilePath, keyFilePath, pkcs12FilePath interface{}) (tlsConfig *tls.Config, err error) {
	if certFilePath == nil && keyFilePath == nil && pkcs12FilePath == nil {
		if w.certPool != nil {
			tlsConfig = &tls.Config{
				Certificates:       []tls.Certificate{w.certificate},
				RootCAs:            w.certPool,
				InsecureSkipVerify: true,
			}
			return tlsConfig, nil
		}
	}
	if certFilePath != nil && keyFilePath != nil && pkcs12FilePath != nil {
		cert, err := ioutil.ReadFile(certFilePath.(string))
		if err != nil {
			return nil, fmt.Errorf("ioutil.ReadFile：%w", err)
		}
		key, err := ioutil.ReadFile(keyFilePath.(string))
		if err != nil {
			return nil, fmt.Errorf("ioutil.ReadFile：%w", err)
		}
		pkcs, err := ioutil.ReadFile(pkcs12FilePath.(string))
		if err != nil {
			return nil, fmt.Errorf("ioutil.ReadFile：%w", err)
		}
		pkcsPool := x509.NewCertPool()
		pkcsPool.AppendCertsFromPEM(pkcs)
		certificate, err := tls.X509KeyPair(cert, key)
		if err != nil {
			return nil, fmt.Errorf("tls.LoadX509KeyPair：%w", err)
		}
		tlsConfig = &tls.Config{
			Certificates:       []tls.Certificate{certificate},
			RootCAs:            pkcsPool,
			InsecureSkipVerify: true}
		return tlsConfig, nil
	}
	return nil, errors.New("cert paths must all nil or all not nil")
}

func (w *wxApp) Orderquery(req OrderqueryReq) (res OrderqueryRes, err error) {
	var result OrderqueryRes
	reqUrl := "https://api.mch.weixin.qq.com/pay/orderquery"
	type requestMapStruct struct {
		Appid      string `xml:"appid"`
		MchId      string `xml:"mch_id"`
		NonceStr   string `xml:"nonce_str"`
		OutTradeNo string `xml:"out_trade_no"`
		Sign       string `xml:"sign"`
	}
	requestMap := requestMapStruct{
		Appid:      w.AppId,
		MchId:      w.PayMchid,
		NonceStr:   req.NonceStr,
		OutTradeNo: req.OutTradeNo,
	}
	requestMapSgin := map[string]interface{}{
		"appid":        w.AppId,
		"mch_id":       w.PayMchid,
		"nonce_str":    req.NonceStr,
		"out_trade_no": req.OutTradeNo,
	}
	sign := w.makeSign(requestMapSgin, SignType_MD5, w.PayApikey)
	requestMap.Sign = sign
	httpClient := xhttp.NewClient()
	requestMapStr, err := xml.Marshal(requestMap)
	if err != nil {
		fmt.Println("requestMapStr_err", err)
	}
	responseBody, bs, errs := httpClient.Type(xhttp.TypeXML).Post(reqUrl).SendString(string(requestMapStr[:])).EndBytes()
	if len(errs) > 0 {
		return result, errs[0]
	}
	if responseBody.StatusCode != 200 {
		return result, errors.New(fmt.Sprintf("HTTP Request Error, StatusCode = %d", responseBody.StatusCode))
	}
	//判断是否请求异常出错(返回的是html)
	if strings.Contains(string(bs), "HTML") || strings.Contains(string(bs), "html") {
		return result, errors.New(string(bs))
	}
	if err = xml.Unmarshal(bs, &result); err != nil {
		return result, fmt.Errorf("xml.Unmarshal(%s)：%w", string(bs), err)
	}
	return result, nil
}

func (w *wxApp) Unifiedorder(req UnifiedorderReq) (res UnifiedorderRes, err error) {
	var result UnifiedorderRes
	reqUrl := "https://api.mch.weixin.qq.com/pay/unifiedorder"
	type requesStruct struct {
		Appid          string `xml:"appid"`
		MchId          string `xml:"mch_id"`
		NonceStr       string `xml:"nonce_str"`
		Body           string `xml:"body"`
		OutTradeNo     string `xml:"out_trade_no"`
		TotalFee       int64  `xml:"total_fee"`
		SpbillCreateIp string `xml:"spbill_create_ip"`
		NotifyUrl      string `xml:"notify_url"`
		TradeType      string `xml:"trade_type"`
		Openid         string `xml:"openid"`
		Sign           string `xml:"sign"`
	}
	requestMap := requesStruct{
		Appid:          w.AppId,
		MchId:          w.PayMchid,
		NonceStr:       req.NonceStr,
		Body:           req.Body,
		OutTradeNo:     req.OutTradeNo,
		TotalFee:       req.TotalFee,
		SpbillCreateIp: req.SpbillCreateIp,
		NotifyUrl:      req.NotifyUrl,
		TradeType:      "JSAPI",
		Openid:         req.Openid,
	}
	requestMapSign := map[string]interface{}{
		"appid":            w.AppId,
		"mch_id":           w.PayMchid,
		"nonce_str":        req.NonceStr,
		"body":             req.Body,
		"out_trade_no":     req.OutTradeNo,
		"total_fee":        req.TotalFee,
		"spbill_create_ip": req.SpbillCreateIp,
		"notify_url":       req.NotifyUrl,
		"trade_type":       "JSAPI",
		"openid":           req.Openid,
	}
	sign := w.makeSign(requestMapSign, SignType_MD5, w.PayApikey)
	requestMap.Sign = sign
	httpClient := xhttp.NewClient()
	requestMapStr, err := xml.Marshal(requestMap)
	if err != nil {
		fmt.Println("requestMapStr_err", err)
	}
	responseBody, bs, errs := httpClient.Type(xhttp.TypeXML).Post(reqUrl).SendString(string(requestMapStr[:])).EndBytes()

	if len(errs) > 0 {
		return result, errs[0]
	}
	if responseBody.StatusCode != 200 {
		return result, errors.New(fmt.Sprintf("HTTP Request Error, StatusCode = %d", responseBody.StatusCode))
	}
	//判断是否请求异常出错(返回的是html)
	if strings.Contains(string(bs), "HTML") || strings.Contains(string(bs), "html") {
		return result, errors.New(string(bs))
	}

	if err = xml.Unmarshal(bs, &result); err != nil {
		return result, fmt.Errorf("xml.Unmarshal(%s)：%w", string(bs), err)
	}

	packageVal := "prepay_id=" + result.PrepayId
	timeStamp := strconv.FormatInt(req.TimeStamp, 10)
	paySign := GetMiniPaySign(w.AppId, result.NonceStr, packageVal, "MD5", timeStamp, w.PayApikey)
	result.PaySign = paySign

	return result, nil
}

// GetMiniPaySign JSAPI支付，统一下单获取支付参数后，再次计算出小程序用的paySign
//	appId：APPID
//	nonceStr：随即字符串
//	packages：统一下单成功后拼接得到的值
//	signType：签名类型
//	timeStamp：时间
//	ApiKey：API秘钥值
//	微信小程序支付API：https://developers.weixin.qq.com/miniprogram/dev/api/open-api/payment/wx.requestPayment.html
//	微信小程序支付PaySign计算文档：https://pay.weixin.qq.com/wiki/doc/api/wxa/wxa_api.php?chapter=7_7&index=3
func GetMiniPaySign(appId, nonceStr, packages, signType, timeStamp, apiKey string) (paySign string) {
	var (
		buffer strings.Builder
		h      hash.Hash
	)
	buffer.WriteString("appId=")
	buffer.WriteString(appId)
	buffer.WriteString("&nonceStr=")
	buffer.WriteString(nonceStr)
	buffer.WriteString("&package=")
	buffer.WriteString(packages)
	buffer.WriteString("&signType=")
	buffer.WriteString(signType)
	buffer.WriteString("&timeStamp=")
	buffer.WriteString(timeStamp)
	buffer.WriteString("&key=")
	buffer.WriteString(apiKey)
	if signType == SignType_HMAC_SHA256 {
		h = hmac.New(sha256.New, []byte(apiKey))
	} else {
		h = md5.New()
	}
	h.Write([]byte(buffer.String()))
	return strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
}

//生成签名
func (w *wxApp) makeSign(params map[string]interface{}, signType string, payApikey string) (sign string) {
	var h hash.Hash
	h = md5.New()
	if signType == SignType_HMAC_SHA256 {
		h = hmac.New(sha256.New, []byte(payApikey))
	} else {
		h = md5.New()
	}
	h.Write([]byte(encodeWeChatSignParams(params, payApikey)))
	return strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
}

// 生成请求XML的Body体
func generateXml(bm map[string]interface{}) (reqXml string) {
	bs, err := xml.Marshal(bm)
	if err != nil {
		return gotil.NULL
	}
	return string(bs)
}

// ("bar=baz&foo=quux") sorted by key.
func encodeWeChatSignParams(params map[string]interface{}, payApikey string) string {
	var (
		buf     strings.Builder
		keyList []string
	)
	for k := range params {
		keyList = append(keyList, k)
	}
	sort.Strings(keyList)
	for _, k := range keyList {
		value, ok := params[k]
		if !ok {
			continue
		}
		v, ok := value.(string)
		if !ok {
			v = convertToString(value)
		}
		buf.WriteString(k)
		buf.WriteByte('=')
		buf.WriteString(v)
		buf.WriteByte('&')
	}
	buf.WriteString("key")
	buf.WriteByte('=')
	buf.WriteString(payApikey)
	return buf.String()
}

func convertToString(v interface{}) (str string) {
	if v == nil {
		return ""
	}
	var (
		bs  []byte
		err error
	)
	if bs, err = json.Marshal(v); err != nil {
		return ""
	}
	str = string(bs)
	return
}

type getUnlimitedResponse struct {
	ErrCode int    `json:"errcode"` //
	ErrMsg  string `json:"errmsg"`  //错误信息
}

func (w *wxApp) GetUnlimited(accessToken string, req GetUnlimitedReq) (base64Byte []byte, err error) {
	reqUrl := "https://api.weixin.qq.com/wxa/getwxacodeunlimit?access_token=" + accessToken + ""
	jsonStr, err := json.Marshal(req)
	resp, err := http.Post(reqUrl, "application/json", bytes.NewReader(jsonStr))
	if err != nil {
		return nil, errors.New("do request error: " + err.Error())
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	if resp.Header["Content-Type"][0] != "image/jpeg" {
		var response getUnlimitedResponse
		err := json.Unmarshal(body[:], &response)
		if err != nil {
			return nil, errors.New("json.Unmarshal error: " + err.Error())
		}
		return nil, errors.New(response.ErrMsg)
	}
	return body, nil
}

type DecryptWXOpenDataResponse struct {
	OpenId    string    `json:"openId"`
	NickName  string    `json:"nickName"`  //昵称
	Gender    int64     `json:"gender"`    //性别 1 男 0女
	Language  string    `json:"language"`  //语言
	City      string    `json:"city"`      //市
	Province  string    `json:"province"`  //省
	Country   string    `json:"country"`   //国家
	AvatarUrl string    `json:"avatarUrl"` //头像地址
	UnionId   string    `json:"unionId"`   //头像地址
	Watermark watermark `json:"watermark"`
}

type watermark struct {
	Timestamp int64  `json:"timestamp"`
	Appid     string `json:"appid"`
}

type DecryptWXOpenDataPhoneResponse struct {
	PhoneNumber     string    `json:"phoneNumber"`
	PurePhoneNumber string    `json:"purePhoneNumber"`
	CountryCode     string    `json:"countryCode"`
	Watermark       watermark `json:"watermark"`
}

func (w *wxApp) DecryptWXOpenDataPhone(req DecryptWXOpenDataReq) (res DecryptWXOpenDataPhoneRes, err error) {
	var result DecryptWXOpenDataPhoneRes
	decodeBytes, err := base64.StdEncoding.DecodeString(req.EncryptData)
	if err != nil {
		return result, errors.New("EncryptData decode string error:" + err.Error())
	}
	sessionKeyBytes, err := base64.StdEncoding.DecodeString(req.SessionKey)
	if err != nil {
		return result, errors.New("sessionKey decode string error:" + err.Error())
	}
	ivBytes, err := base64.StdEncoding.DecodeString(req.Iv)
	if err != nil {
		return result, errors.New("iv decode string error:" + err.Error())
	}
	dataBytes, err := AesDecrypt(decodeBytes, sessionKeyBytes, ivBytes)
	if err != nil {
		return result, errors.New("aes decrypt error:" + err.Error())
	}
	m := DecryptWXOpenDataPhoneResponse{}
	err = json.Unmarshal(dataBytes, &m)
	if err != nil {
		return result, errors.New("json.Unmarshal error: " + err.Error())
	}
	res.PurePhoneNumber = m.PurePhoneNumber
	res.CountryCode = m.CountryCode
	res.PhoneNumber = m.PhoneNumber
	return res, nil

}

func (w *wxApp) DecryptWXOpenData(req DecryptWXOpenDataReq) (res DecryptWXOpenDataRes, err error) {
	var result DecryptWXOpenDataRes
	decodeBytes, err := base64.StdEncoding.DecodeString(req.EncryptData)
	if err != nil {
		return result, errors.New("EncryptData decode string error:" + err.Error())
	}
	sessionKeyBytes, err := base64.StdEncoding.DecodeString(req.SessionKey)
	if err != nil {
		return result, errors.New("sessionKey decode string error:" + err.Error())
	}
	ivBytes, err := base64.StdEncoding.DecodeString(req.Iv)
	if err != nil {
		return result, errors.New("iv decode string error:" + err.Error())
	}
	dataBytes, err := AesDecrypt(decodeBytes, sessionKeyBytes, ivBytes)
	if err != nil {
		return result, errors.New("aes decrypt error:" + err.Error())
	}
	m := DecryptWXOpenDataResponse{}
	err = json.Unmarshal(dataBytes, &m)
	if err != nil {
		return result, errors.New("json.Unmarshal error: " + err.Error())
	}
	if m.Watermark.Appid != w.AppId {
		return result, errors.New("invalid appid")
	}
	res.OpenId = m.OpenId
	res.NickName = m.NickName
	res.Gender = m.Gender
	res.Language = m.Language
	res.City = m.City
	res.Province = m.Province
	res.Country = m.Country
	res.AvatarUrl = m.AvatarUrl
	res.UnionId = m.UnionId
	return res, nil

}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)

	unpadding := int(origData[length-1])

	return origData[:(length - unpadding)]

}

func AesDecrypt(crypted, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	//获取的数据尾端有'/x0e'占位符,去除它
	if len(origData) > 0 {
		origData = xaes.PKCS7UnPadding(origData)
	}
	return origData, nil
}

type getPaidUnionIdResponse struct {
	Unionid string `json:"unionid"` //用户在开放平台的唯一标识符，在满足 UnionID 下发条件的情况下会返回，详见 UnionID 机制说明。
	ErrCode int    `json:"errcode"` //
	ErrMsg  string `json:"errmsg"`  //错误信息
}

func (w *wxApp) GetPaidUnionId(req GetPaidUnionIdReq) (res GetPaidUnionIdRes, err error) {
	var result GetPaidUnionIdRes
	reqUrl := "https://api.weixin.qq.com/wxa/getpaidunionid?access_token=" + req.AccessToken + "&openid=" + req.Openid + ""
	resp, err := http.Get(reqUrl)
	if err != nil {
		return result, errors.New("request error:" + err.Error())
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return result, errors.New("read body error: " + err.Error())
	}
	var Response getPaidUnionIdResponse
	if err := json.Unmarshal(body, &Response); err != nil {
		return result, errors.New("json.Unmarshal error: " + err.Error())
	}
	if Response.ErrCode != 0 {
		return result, errors.New(Response.ErrMsg)
	}
	result.Unionid = Response.Unionid
	return result, nil
}

type getAccessTokenResponse struct {
	AccessToken string `json:"access_token"` //获取到的凭证
	ExpiresIn   int64  `json:"expires_in"`   //凭证有效时间，单位：秒。目前是7200秒之内的值。
	ErrCode     int    `json:"errcode"`
	ErrMsg      string `json:"errmsg"` //错误信息
}

func (w *wxApp) GetAccessToken() (res GetAccessTokenRes, err error) {
	var result GetAccessTokenRes
	reqUrl := "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=" + w.AppId + "&secret=" + w.AppSecret + ""
	resp, err := http.Get(reqUrl)
	if err != nil {
		return result, errors.New("request error:" + err.Error())
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return result, errors.New("read body error: " + err.Error())
	}
	var Response getAccessTokenResponse
	if err := json.Unmarshal(body, &Response); err != nil {
		return result, errors.New("json.Unmarshal error: " + err.Error())
	}
	if Response.ErrCode != 0 {
		return result, errors.New(Response.ErrMsg)
	}
	result.AccessToken = Response.AccessToken
	result.ExpiresIn = Response.ExpiresIn
	return result, nil
}

type code2SessionResponse struct {
	Openid     string `json:"openid"`      //用户唯一标识
	SessionKey string `json:"session_key"` //会话密钥
	Unionid    string `json:"unionid"`     //用户在开放平台的唯一标识符，在满足 UnionID 下发条件的情况下会返回，详见 UnionID 机制说明。
	ErrCode    int    `json:"errcode"`     //-1	系统繁忙，此时请开发者稍候再试 0	请求成功 40029	code 无效 45011	频率限制，每个用户每分钟100次
	ErrMsg     string `json:"errmsg"`      //错误信息
}

func (w *wxApp) Code2Session(req Code2SessionReq) (res Code2SessionRes, err error) {
	reqUrl := "https://api.weixin.qq.com/sns/jscode2session?appid=" + w.AppId + "&secret=" + w.AppSecret + "&js_code=" + req.JsCode + "&grant_type=authorization_code"
	var result Code2SessionRes
	resp, err := http.Get(reqUrl)
	if err != nil {
		return result, errors.New("request error:" + err.Error())
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return result, errors.New("read body error: " + err.Error())
	}
	var Response code2SessionResponse
	if err := json.Unmarshal(body, &Response); err != nil {
		return result, errors.New("json.Unmarshal error: " + err.Error())
	}
	if Response.ErrCode != 0 {
		return result, errors.New(Response.ErrMsg)
	}
	result.Openid = Response.Openid
	result.SessionKey = Response.SessionKey
	result.Unionid = Response.Unionid
	return result, nil
}

func NewWxApp(appId, appSecret, payMchid, payApikey string) BasicWxInterface {
	return &wxApp{
		AppId:     appId,
		AppSecret: appSecret,
		PayMchid:  payMchid,
		PayApikey: payApikey,
	}
}
