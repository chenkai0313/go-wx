package go_wx

type BasicWxInterface interface {
	Code2Session(req Code2SessionReq) (res Code2SessionRes, err error)                          //登录凭证校验,通过js_code获取openid,unionid,需要授权
	GetAccessToken() (res GetAccessTokenRes, err error)                                         //获取小程序全局唯一后台接口调用凭据（access_token）,有效期目前为 2 个小时，需定时刷新
	GetPaidUnionId(req GetPaidUnionIdReq) (res GetPaidUnionIdRes, err error)                    //用户支付完成后，获取该用户的 UnionId，无需用户授权。
	DecryptWXOpenData(req DecryptWXOpenDataReq) (res DecryptWXOpenDataRes, err error)           //解密用户敏感信息
	DecryptWXOpenDataPhone(req DecryptWXOpenDataReq) (res DecryptWXOpenDataPhoneRes, err error) //解密用户手机号敏感信息
	GetUnlimited(accessToken string, req GetUnlimitedReq) (base64Byte []byte, err error)        //获取小程序码，适用于需要的码数量极多的业务场景。通过该接口生成的小程序码，永久有效，数量暂无限制。
	Unifiedorder(req UnifiedorderReq) (res UnifiedorderRes, err error)                          //支付统一下单接口
	Orderquery(req OrderqueryReq) (res OrderqueryRes, err error)                                //查询订单
	Refund(req RefundReq) (res RefundRes, err error)                                            //申请退款
	Transfer(req TransferReq) (res TransferRes, err error)                                      //企业付款到零钱
}
type TransferReq struct {
	NonceStr       string `xml:"nonce_str" json:"nonce_str"`
	PartnerTradeNo string `xml:"partner_trade_no" json:"partner_trade_no"` //系统的订单号
	Openid         string `xml:"openid" json:"openid"`
	Amount         int64  `xml:"amount" json:"amount"`
	Desc           string `xml:"desc" json:"desc"`
	CertFilePath   string //双向证书路径
	KeyFilePath    string //双向证书路径
	Pkcs12FilePath string //双向证书路径
}
type TransferRes struct {
	ReturnCode     string `xml:"return_code" json:"return_code"`
	ReturnMsg      string `xml:"return_msg" json:"return_msg"`
	MchAppid       string `xml:"mch_appid" json:"mch_appid"`
	Mchid          string `xml:"mchid" json:"mchid"`
	DeviceInfo     string `xml:"device_info" json:"device_info"`
	NonceStr       string `xml:"nonce_str" json:"nonce_str"`
	ResultCode     string `xml:"result_code" json:"result_code"`           //SUCCESS/FAIL，注意：当状态为FAIL时，存在业务结果未明确的情况。如果状态为FAIL，请务必关注错误代码（err_code字段），通过查询查询接口确认此次付款的结果。
	ErrCode        string `xml:"err_code" json:"err_code"`                 //错误码信息，注意：出现未明确的错误码时（SYSTEMERROR等），请务必用原商户订单号重试，或通过查询接口确认此次付款的结果。
	ErrCodeDes     string `xml:"err_code_des" json:"err_code_des"`         //
	PartnerTradeNo string `xml:"partner_trade_no" json:"partner_trade_no"` //商户订单号，需保持历史全局唯一性(只能是字母或者数字，不能包含有其它字符)
	PaymentNo      string `xml:"payment_no" json:"payment_no"`             //企业付款成功，返回的微信付款单号
	PaymentTime    string `xml:"payment_time" json:"payment_time"`         //企业付款成功时间
}
type RefundReq struct {
	NonceStr       string //随机字符串，长度要求在32位以内。
	OutTradeNo     string //商户系统内部订单号，要求32个字符内，只能是数字、大小写字母_-|*且在同一个商户号下唯一。详见商户订单号
	OutRefundNo    string //商户系统内部的退款单号，商户系统内部唯一，只能是数字、大小写字母_-|*@ ，同一退款单号多次请求只退一笔。
	TotalFee       int64  //订单总金额，单位为分，只能为整数，详见支付金额
	RefundFee      int64  //退款总金额，订单总金额，单位为分，只能为整数，详见支付金额
	NotifyUrl      string //异步接收微信支付退款结果通知的回调地址，通知URL必须为外网可访问的url，不允许带参数 如果参数中传了notify_url，则商户平台上配置的回调地址将不会生效。
	CertFilePath   string //双向证书路径
	KeyFilePath    string //双向证书路径
	Pkcs12FilePath string //双向证书路径
}

type RefundRes struct {
	ReturnCode          string `xml:"return_code" json:"return_code"`
	ReturnMsg           string `xml:"return_msg" json:"return_msg"`
	ResultCode          string `xml:"result_code" json:"result_code"`
	ErrCode             string `xml:"err_code" json:"err_code"`
	ErrCodeDes          string `xml:"err_code_des" json:"err_code_des"`
	Appid               string `xml:"appid" json:"appid"`
	SubAppid            string `xml:"sub_appid" json:"sub_appid"`
	MchId               string `xml:"mch_id" json:"mch_id"`
	SubMchId            string `xml:"sub_mch_id" json:"sub_mch_id"`
	NonceStr            string `xml:"nonce_str" json:"nonce_str"`
	Sign                string `xml:"sign" json:"sign"`
	TransactionId       string `xml:"transaction_id" json:"transaction_id"`
	OutTradeNo          string `xml:"out_trade_no" json:"out_trade_no"`
	OutRefundNo         string `xml:"out_refund_no" json:"out_refund_no"`
	RefundId            string `xml:"refund_id" json:"refund_id"`
	RefundFee           string `xml:"refund_fee" json:"refund_fee"`
	SettlementRefundFee string `xml:"settlement_refund_fee" json:"settlement_refund_fee"`
	TotalFee            string `xml:"total_fee" json:"total_fee"`
	SettlementTotalFee  string `xml:"settlement_total_fee" json:"settlement_total_fee"`
	FeeType             string `xml:"fee_type" json:"fee_type"`
	CashFee             string `xml:"cash_fee" json:"cash_fee"`
	CashFeeType         string `xml:"cash_fee_type" json:"cash_fee_type"`
	CashRefundFee       string `xml:"cash_refund_fee" json:"cash_refund_fee"`
	CouponType0         string `xml:"coupon_type_0" json:"coupon_type_0"`
	CouponType1         string `xml:"coupon_type_1" json:"coupon_type_1"`
	CouponType2         string `xml:"coupon_type_2" json:"coupon_type_2"`
	CouponRefundFee     string `xml:"coupon_refund_fee" json:"coupon_refund_fee"`
	CouponRefundFee0    string `xml:"coupon_refund_fee_0" json:"coupon_refund_fee_0"`
	CouponRefundFee1    string `xml:"coupon_refund_fee_1" json:"coupon_refund_fee_1"`
	CouponRefundFee2    string `xml:"coupon_refund_fee_2" json:"coupon_refund_fee_2"`
	CouponRefundCount   string `xml:"coupon_refund_count" json:"coupon_refund_count"`
	CouponRefundId0     string `xml:"coupon_refund_id_0" json:"coupon_refund_id_0"`
	CouponRefundId1     string `xml:"coupon_refund_id_1" json:"coupon_refund_id_1"`
	CouponRefundId2     string `xml:"coupon_refund_id_2" json:"coupon_refund_id_2"`
}

type OrderqueryReq struct {
	NonceStr   string //随机字符串，长度要求在32位以内。
	OutTradeNo string //商户系统内部订单号，要求32个字符内，只能是数字、大小写字母_-|*且在同一个商户号下唯一。详见商户订单号
}

type OrderqueryRes struct {
	ReturnCode         string `xml:"return_code" json:"return_code"`
	ReturnMsg          string `xml:"return_msg" json:"return_msg"`
	Appid              string `xml:"appid" json:"appid"`
	SubAppid           string `xml:"sub_appid" json:"sub_appid"`
	MchId              string `xml:"mch_id" json:"mch_id"`
	SubMchId           string `xml:"sub_mch_id" json:"sub_mch_id"`
	NonceStr           string `xml:"nonce_str" json:"nonce_str"`
	Sign               string `xml:"sign" json:"sign"`
	ResultCode         string `xml:"result_code" json:"result_code"`
	ErrCode            string `xml:"err_code" json:"err_code"`
	ErrCodeDes         string `xml:"err_code_des" json:"err_code_des"`
	DeviceInfo         string `xml:"device_info" json:"device_info"`
	Openid             string `xml:"openid" json:"openid"`
	IsSubscribe        string `xml:"is_subscribe" json:"is_subscribe"`
	TradeType          string `xml:"trade_type" json:"trade_type"`
	TradeState         string `xml:"trade_state" json:"trade_state"`
	BankType           string `xml:"bank_type" json:"bank_type"`
	TotalFee           int64  `xml:"total_fee" json:"total_fee"`
	SettlementTotalFee string `xml:"settlement_total_fee" json:"settlement_total_fee"`
	FeeType            string `xml:"fee_type" json:"fee_type"`
	CashFee            string `xml:"cash_fee" json:"cash_fee"`
	CashFeeType        string `xml:"cash_fee_type" json:"cash_fee_type"`
	CouponFee          string `xml:"coupon_fee" json:"coupon_fee"`
	CouponCount        string `xml:"coupon_count" json:"coupon_count"`
	CouponType0        string `xml:"coupon_type_0" json:"coupon_type_0"`
	CouponType1        string `xml:"coupon_type_1" json:"coupon_type_1"`
	CouponType2        string `xml:"coupon_type_2" json:"coupon_type_2"`
	CouponId0          string `xml:"coupon_id_0" json:"coupon_id_0"`
	CouponId1          string `xml:"coupon_id_1" json:"coupon_id_1"`
	CouponId2          string `xml:"coupon_id_2" json:"coupon_id_2"`
	CouponFee0         string `xml:"coupon_fee_0" json:"coupon_fee_0"`
	CouponFee1         string `xml:"coupon_fee_1" json:"coupon_fee_1"`
	CouponFee2         string `xml:"coupon_fee_2" json:"coupon_fee_2"`
	TransactionId      string `xml:"transaction_id" json:"transaction_id"`
	OutTradeNo         string `xml:"out_trade_no" json:"out_trade_no"`
	Attach             string `xml:"attach" json:"attach"`
	TimeEnd            string `xml:"time_end" json:"time_end"`
	TradeStateDesc     string `xml:"trade_state_desc" json:"trade_state_desc"`
}

type UnifiedorderReq struct {
	NonceStr       string //随机字符串，长度要求在32位以内。
	Body           string //商品简单描述，该字段请按照规范传递，具体请见参数规定
	OutTradeNo     string //商户系统内部订单号，要求32个字符内，只能是数字、大小写字母_-|*且在同一个商户号下唯一。详见商户订单号
	TotalFee       int64  //订单总金额，单位为分，详见支付金额
	SpbillCreateIp string //支持IPV4和IPV6两种格式的IP地址。调用微信支付API的机器IP
	NotifyUrl      string //异步接收微信支付结果通知的回调地址，通知url必须为外网可访问的url，不能携带参数。
	Openid         string
	TimeStamp      int64
}

type UnifiedorderRes struct {
	ReturnCode string `xml:"return_code" json:"return_code"`
	ReturnMsg  string `xml:"return_msg" json:"return_msg"`
	Appid      string `xml:"appid" json:"appid"`
	MchId      string `xml:"mch_id" json:"mch_id"`
	NonceStr   string `xml:"nonce_str" json:"nonce_str"`       ////随机字符串，长度要求在32位以内。
	Sign       string `xml:"sign" json:"sign"`                 //签名
	ResultCode string `xml:"result_code" json:"result_code"`   //SUCCESS/FAIL
	ErrCode    string `xml:"err_code" json:"err_code"`         //错误代码 查看小程序支付文档
	ErrCodeDes string `xml:"err_code_des" json:"err_code_des"` //错误代码描述
	TradeType  string `xml:"trade_type" json:"trade_type"`     //交易类型
	PrepayId   string `xml:"prepay_id" json:"prepay_id"`       //预支付交易会话标识
	CodeUrl    string `xml:"code_url" json:"code_url"`         //二维码链接
	PaySign    string `xml:"pay_sign" json:"pay_sign"`
}

type GetUnlimitedReq struct {
	Scene     string    `json:"scene"`      //最大32个可见字符，只支持数字，大小写英文以及部分特殊字符：!#$&'()*+,/:;=?@-._~，其它字符请自行编码为合法字符（因不支持%，中文无法使用 urlencode 处理，请使用其他编码方式）
	Page      string    `json:"page"`       //必须是已经发布的小程序存在的页面（否则报错），例如 pages/index/index, 根路径前不要填加 /,不能携带参数（参数请放在scene字段里），如果不填写这个字段，默认跳主页面
	Width     int64     `json:"width"`      //二维码的宽度，单位 px，最小 280px，最大 1280px 默认430
	AutoColor bool      `json:"auto_color"` //自动配置线条颜色，如果颜色依然是黑色，则说明不建议配置主色调，默认 false
	LineColor LineColor `json:"line_color"` //auto_color 为 false 时生效，使用 rgb 设置颜色 例如 {"r":"xxx","g":"xxx","b":"xxx"} 十进制表示
	IsHyaline bool      `json:"is_hyaline"` //是否需要透明底色，为 true 时，生成透明底色的小程序 默认 false
}

type LineColor struct {
	R string `json:"r"`
	G string `json:"g"`
	B string `json:"b"`
}

type DecryptWXOpenDataRes struct {
	NickName  string //昵称
	OpenId    string //昵称
	Gender    int64  //性别 1 男 0女
	Language  string //语言
	City      string //市
	Province  string //省
	Country   string //国家
	AvatarUrl string //头像地址
	UnionId   string //头像地址
}

type DecryptWXOpenDataPhoneRes struct {
	PhoneNumber     string //用户绑定的手机号（国外手机号会有区号）
	PurePhoneNumber string //没有区号的手机号
	CountryCode     string //区号
}

type DecryptWXOpenDataReq struct {
	SessionKey  string //会话密钥
	EncryptData string //加密的数据
	Iv          string //矢向向量
}

type GetPaidUnionIdReq struct {
	AccessToken string //获取到的凭证
	Openid      string //用户唯一标识
}

type GetPaidUnionIdRes struct {
	Unionid string //用户在开放平台的唯一标识符，在满足 UnionID 下发条件的情况下会返回，详见 UnionID 机制说明。
}

type GetAccessTokenRes struct {
	AccessToken string //获取到的凭证
	ExpiresIn   int64  //凭证有效时间，单位：秒。目前是7200秒之内的值。
}

type Code2SessionReq struct {
	JsCode string //登录时获取的 code
}

type Code2SessionRes struct {
	Openid     string //用户唯一标识
	SessionKey string //会话密钥
	Unionid    string //用户在开放平台的唯一标识符，在满足 UnionID 下发条件的情况下会返回，详见 UnionID 机制说明。
}
