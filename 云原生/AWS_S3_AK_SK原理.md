## 0x00 AWS S3 bucket
AWS S3（Simple Storage Service）是一种对象存储服务，设计用来存储和处理海量数据。在S3中，数据被存储为对象，每个对象包含一个key，数据本身和元数据标签等。

## 0x01 对象存储
对象存储是一种数据存储架构，用来存储和管理大规模的非结构化数据，包括文档、图像、视频等。它将数据存储为对象（Object），每个对象包含数据本身、元数据（用来描述数据的属性）和一个唯一标识符（ID）。对象存储不依赖于层级目录结构，数据可以在全球范围内分布存储并通过唯一ID直接访问。

## 0x02 AK/SK概念
AK和SK是在云存储过程中用于身份验证和授权的一组密钥对。  

AK：Access Key 访问密钥ID，AK是公开的全局唯一的字符串标识符，用来标识用户；  
SK：Secret Access Key秘密访问密钥，这是需要保密的密钥，类似于密码，对发送到服务的请求签名；  
每个AK都有对应的SK，他们成对出现，共同完成安全认证的过程。

## 0x03 AK/SK认证流程
1. 客户端首先要构建 HTTP 请求字符串，包括请求方法、URL路径、请求头和请求体等；
2. 对请求信息规范化处理，按照字典顺序对查询参数排序，然后保留并处理需要签名的头部信息，使用SHA-256处理请求体，生成一个固定长度的哈希值；
3. 把规范化的信息拼接成一个代签名字符串；
4. 使用SK对待签名的字符串进行加密哈希处理，通常使用HMAC-SHA256算法，生成一个签名值；
5. 把生成的签名值附加到 HTTP 请求中，通常会放在请求头部的 Authorization 字段中；
6. 服务器收到请求后，根据AK对应的SK，用同样的步骤生成签名，进行比较以确认用户身份。

## 0x04 python链接S3存储桶进行操作
python写法：
```python
# boto3是针对S3云存储的Python SDK工具
import boto3
from datetime import datetime, timedelta
# 定义 endpoint、access key 和 secret key
endpoint_url = 'http://*************'
access_key = '****'
secret_key = '****'
 
# 创建 S3 客户端实例并指定 endpoint 和凭证信息
s3 = boto3.client('s3',
                  endpoint_url=endpoint_url,
                  aws_access_key_id=access_key,
                  aws_secret_access_key=secret_key,
                  verify=False)  
                  # 如果不需要SSL验证，可以设置verify=False，即http或者https
 
# 列出所有的桶
responses = s3.list_buckets()
buckets = [bucket['Name'] for bucket in responses['Buckets']]
print('All of Buckets:', buckets)
```
Go写法：
```golang
package main
import (
	"fmt"
	"os"
    "github.com/aws/aws-sdk-go/aws"
    "github.com/aws/aws-sdk-go/aws/credentials"
    _ "github.com/aws/aws-sdk-go/service/s3/s3manager"
    "github.com/aws/aws-sdk-go/aws/session"
    "github.com/aws/aws-sdk-go/service/s3"
)
func main() {

    access_key := "xxxxxxxxxxxxx"
    secret_key := "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	end_point := "http://xx.xx.xx.xx:7480" //endpoint设置，不要动
	
	sess, err := session.NewSession(&aws.Config{
        Credentials:      credentials.NewStaticCredentials(access_key, secret_key, ""),
        Endpoint:         aws.String(end_point),
        Region:           aws.String("us-east-1"),
        DisableSSL:       aws.Bool(true),
        S3ForcePathStyle: aws.Bool(false), //virtual-host style方式，不要修改
	})
}
```
## 0x05 项目相关
第一步：创建HTTP请求，并定义关键参数。使用GET方法，服务类型为STS，AWS的安全令牌服务（Security Token Service），指定host，region和endpoint。获取当前时间戳。
```golang
    // REQUEST VALUES.
	method := "GET"
	service := "sts"
	host := "sts.amazonaws.com"
	region := "us-east-1"
	endpoint := "https://sts.amazonaws.com"
	now := time.Now().UTC()
	datestamp := now.Format("20060102")
	amzDate := now.Format("20060102T150405Z0700")
    //使用NewRequestWithContext方法创建HTTP请求
	req, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
	if err != nil {
		return false, nil, err
	}
    //设置 HTTP 请求的 Accept 头，告诉服务器客户端期望的响应格式为 application/json
	req.Header.Set("Accept", "application/json")
```
第二步：构建规范请求，准备AWS signature v4 所需的必要信息。规范请求是生成签名字符串的基础，确保请求在传输过程中没有被篡改，并且只能由持有正确凭证的人发起。
```golang
    // TASK 2: CREATE A CANONICAL REQUEST.创建一个规范请求
	// http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
	canonicalURI := "/"
	canonicalHeaders := "host:" + host + "\n" //规范请求头
	signedHeaders := "host"  //用来签名的头部列表
	algorithm := "AWS4-HMAC-SHA256" //签名算法
    //确定凭证作用域，限制凭证有效性
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", datestamp, region, service)

	params := req.URL.Query()
    //Action 设置为 GetCallerIdentity，它是用于获取调用者的身份信息。
	params.Add("Action", "GetCallerIdentity") 
	params.Add("Version", "2011-06-15") //API版本
	params.Add("X-Amz-Algorithm", algorithm) //加密算法
    //AK-ID和标识请求的身份信息
	params.Add("X-Amz-Credential", resIDMatch+"/"+credentialScope) 
	params.Add("X-Amz-Date", amzDate)
	params.Add("X-Amz-Expires", "30")
	params.Add("X-Amz-SignedHeaders", signedHeaders) //哪些请求头参与了签名计算

	canonicalQuerystring := params.Encode()
	payloadHash := GetHash("") // empty payload
    //顺序为：请求方法、URI、规范化查询字符串、规范化头部、签名头部、请求体的哈希值。
	canonicalRequest := method + "\n" + canonicalURI + "\n" + canonicalQuerystring + "\n" + canonicalHeaders + "\n" + signedHeaders + "\n" + payloadHash
```
第三步：创建待签名字符串（String to Sign），签名算法algorithm，请求时间戳amzDate，凭证作用域credentialScope，计算规范请求的哈希值GetHash(canonicalRequest)。创建“待签名字符串”是一个核心步骤。这个字符串包括了签名算法、请求时间戳、凭证作用域以及规范请求的哈希值。这确保了签名过程涵盖了请求的所有重要信息，并为生成最终的签名打下了基础。
```golang
// TASK 3: CREATE THE STRING TO SIGN. 创建待签名字符串
	stringToSign := algorithm + "\n" + amzDate + "\n" + credentialScope + "\n" + GetHash(canonicalRequest)
```
第四步：计算签名，首先 resSecretMatch 是用户的 AWS 秘钥（Secret Access Key），通过在其前面添加字符串 "AWS4"，形成初始的 HMAC 密钥。GetHMAC 函数用来计算 HMAC-SHA256 值。
```golang
    // TASK 4: CALCULATE THE SIGNATURE. 计算签名
	// https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
    //使用密钥 AWS4 + Secret Access Key 和日期戳（datestamp）进行第一次 HMAC 计算。
	hash := GetHMAC([]byte(fmt.Sprintf("AWS4%s", resSecretMatch)), []byte(datestamp))
    //使用上一步计算出的 hash 结果作为密钥，结合 AWS 区域（region），进行第二次 HMAC 计算
    //限制签名只在特定区域内有效
	hash = GetHMAC(hash, []byte(region))
    //同理，结合服务service名称，进行第三次 HMAC 计算
	hash = GetHMAC(hash, []byte(service))
    //以上一步的 hash 结果作为密钥，结合固定字符串 "aws4_request"，进行第四次 HMAC 计算
	hash = GetHMAC(hash, []byte("aws4_request"))

    //最后一步，使用上一步的 hash 结果作为密钥，结合“待签名字符串”（stringToSign），计算最终的 HMAC-SHA256 值
	signature2 := GetHMAC(hash, []byte(stringToSign)) // Get Signature HMAC SHA256
    //最后转换为16进制字符串
	signature := hex.EncodeToString(signature2)
```
第五步，将计算出的签名信息添加到 HTTP 请求中，为请求设置了一些额外的头信息。处理发送到AWS STS服务的HTTP请求响应，根据响应码执行相关操作。
```golang
    // TASK 5: ADD SIGNING INFORMATION TO THE REQUEST.将计算出的签名信息添加到 HTTP 请求中
	// 把签名 signature 作为查询参数添加到请求中
    params.Add("X-Amz-Signature", signature)
	req.Header.Add("Content-type", "application/x-www-form-urlencoded; charset=utf-8")
	req.URL.RawQuery = params.Encode() //URL编码

	client := s.verificationClient
	if client == nil {
		client = defaultVerificationClient
	}

	extraData := map[string]string{
		"rotation_guide": "https://howtorotate.com/docs/tutorials/aws/",
	}

	res, err := client.Do(req)
	if err == nil {
		defer res.Body.Close()
		if res.StatusCode >= 200 && res.StatusCode < 300 {
            //解析响应数据
			identityInfo := identityRes{}
            //json解码器，将响应体的 JSON 数据解码到 identityInfo 结构体中
			err := json.NewDecoder(res.Body).Decode(&identityInfo)
			if err == nil {
				extraData["account"] = identityInfo.GetCallerIdentityResponse.GetCallerIdentityResult.Account
				extraData["user_id"] = identityInfo.GetCallerIdentityResponse.GetCallerIdentityResult.UserID
				extraData["arn"] = identityInfo.GetCallerIdentityResponse.GetCallerIdentityResult.Arn
				return true, extraData, nil
			} else {
				return false, nil, err
			}
		} else if res.StatusCode == 403 {
			
			if retryOn403 {
				return s.verifyMatch(ctx, resIDMatch, resSecretMatch, false)
			}
			var body awsErrorResponseBody
			err = json.NewDecoder(res.Body).Decode(&body)
			if err == nil {
				// All instances of the code I've seen in the wild are PascalCased but this check is
				// case-insensitive out of an abundance of caution
				if strings.EqualFold(body.Error.Code, "InvalidClientTokenId") {
					return false, nil, nil
				} else {
					return false, nil, fmt.Errorf("request returned status %d with an unexpected reason (%s: %s)", res.StatusCode, body.Error.Code, body.Error.Message)
				}
			} else {
				return false, nil, fmt.Errorf("couldn't parse the sts response body (%v)", err)
			}
		} else {
			return false, nil, fmt.Errorf("request to %v returned unexpected status %d", res.Request.URL, res.StatusCode)
		}
	} else {
		return false, nil, err
	}

```
```golang

```