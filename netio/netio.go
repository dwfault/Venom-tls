package netio

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"reflect"
	"regexp"
	"time"

	"github.com/Dliv3/Venom/crypto"
	"github.com/Dliv3/Venom/global"
	"github.com/Dliv3/Venom/utils"
)

// WritePacket write packet to node.Conn
func WritePacket(output io.Writer, packet interface{}) error {
	t := reflect.TypeOf(packet)
	v := reflect.ValueOf(packet)

	if k := t.Kind(); k != reflect.Struct {
		return errors.New("second param is not struct")
	}

	count := t.NumField()
	for i := 0; i < count; i++ {
		val := v.Field(i).Interface()

		// type switch
		switch value := val.(type) {
		case uint16:
			_, err := Write(output, utils.Uint16ToBytes(value))
			if err != nil {
				return err
			}
		case uint32:
			_, err := Write(output, utils.Uint32ToBytes(value))
			if err != nil {
				return err
			}
		case uint64:
			_, err := Write(output, utils.Uint64ToBytes(value))
			if err != nil {
				return err
			}
		case string:
			_, err := Write(output, []byte(value))
			if err != nil {
				return err
			}
		case []byte:
			_, err := Write(output, value)
			if err != nil {
				return err
			}
		case [2]byte:
			_, err := Write(output, value[0:])
			if err != nil {
				return err
			}
		case [4]byte:
			_, err := Write(output, value[0:])
			if err != nil {
				return err
			}
		case [32]byte:
			_, err := Write(output, value[0:])
			if err != nil {
				return err
			}
		default:
			return errors.New("type unsupport")
		}
	}
	return nil
}

// ReadPacket read packet from node.Conn
// packet data start from the packet separator
func ReadPacket(input io.Reader, packet interface{}) error {
	v := reflect.ValueOf(packet)
	t := reflect.TypeOf(packet)

	if v.Kind() == reflect.Ptr && !v.Elem().CanSet() {
		return errors.New("packet is not a reflect. Ptr or elem can not be setted")
	}

	v = v.Elem()

	t = t.Elem()
	count := t.NumField()

	for i := 0; i < count; i++ {
		val := v.Field(i).Interface()
		f := v.FieldByName(t.Field(i).Name)

		// 类型断言
		switch val.(type) {
		case string:
			// 字段为分隔符，只有分隔符字段可被设置成string类型
			// 在处理协议数据包之前，首先读取到协议数据分隔符
			// 分隔符为协议结构体的第一个数据
			if i == 0 {
				separator, err := readUntilSeparator(input, global.PROTOCOL_SEPARATOR)
				if err != nil {
					return err
				}
				f.SetString(separator)
			}
		case uint16:
			var buf [2]byte
			_, err := Read(input, buf[0:])
			if err != nil {
				return err
			}
			f.SetUint(uint64(utils.BytesToUint16(buf[0:])))
		case uint32:
			var buf [4]byte
			_, err := Read(input, buf[0:])
			if err != nil {
				return err
			}
			f.SetUint(uint64(utils.BytesToUint32(buf[0:])))
		case uint64:
			var buf [8]byte
			_, err := Read(input, buf[0:])
			if err != nil {
				return err
			}
			f.SetUint(uint64(utils.BytesToUint64(buf[0:])))
		case []byte:
			// 要求, 未指明长度的字段名需要有字段来指定其长度，并长度字段名为该字段名+Len
			// 如HashID字段是通过HashIDLen指明长度的
			// 并且要求HashIDLen在结构体中的位置在HashID之前
			temp := v.FieldByName(t.Field(i).Name + "Len")
			// 类型断言，要求长度字段类型必须为uint16、uint32或uint64
			var length uint64
			switch lengthTemp := temp.Interface().(type) {
			case uint64:
				length = lengthTemp
			case uint32:
				length = uint64(lengthTemp)
			case uint16:
				length = uint64(lengthTemp)
			}
			// 如果长度为0，就不需要读数据了
			if length != 0 {
				if length > global.MAX_PACKET_SIZE+uint64(crypto.OVERHEAD) {
					return nil
				}
				buf := make([]byte, length)
				_, err := Read(input, buf[0:])
				if err != nil {
					return err
				}
				f.SetBytes(buf)
			}
		case [2]byte:
			var buf [2]byte
			_, err := Read(input, buf[0:])
			if err != nil {
				return err
			}
			f.Set(reflect.ValueOf(buf))
		case [4]byte:
			var buf [4]byte
			_, err := Read(input, buf[0:])
			if err != nil {
				return err
			}
			f.Set(reflect.ValueOf(buf))
		case [32]byte:
			var buf [32]byte
			_, err := Read(input, buf[0:])
			if err != nil {
				return err
			}
			// 使用reflect给array类型赋值的方法
			f.Set(reflect.ValueOf(buf))
		default:
			return errors.New("type unsupport")
		}
	}
	return nil
}

func Read(input io.Reader, buffer []byte) (int, error) {
	n, err := io.ReadFull(input, buffer)
	if err != nil {
		// log.Println("[-]Read Error: ", err)
	}
	return n, err
}

func Write(output io.Writer, buffer []byte) (int, error) {
	if len(buffer) > 0 {
		n, err := output.Write(buffer)
		if err != nil {
			// log.Println("[-]Write Error: ", err)
		}
		return n, err
	}
	return 0, nil
}

// if found, return PROTOCOL_SEPARATOR
func readUntilSeparator(input io.Reader, separator string) (string, error) {
	kmp, _ := utils.NewKMP(separator)
	i := 0
	var one [1]byte
	for {
		_, err := Read(input, one[0:])
		if err != nil {
			return "", err
		}
		if kmp.Pattern[i] == one[0] {
			if i == kmp.Size-1 {
				return kmp.Pattern, nil
			}
			i++
			continue
		}
		if kmp.Prefix[i] > -1 {
			i = kmp.Prefix[i]
		} else {
			i = 0
		}
	}
}

func NetCopy(input, output net.Conn) (err error) {
	defer input.Close()

	buf := make([]byte, global.MAX_PACKET_SIZE)
	for {
		count, err := input.Read(buf)
		if err != nil {
			if err == io.EOF && count > 0 {
				output.Write(buf[:count])
			}
			if err != io.EOF {
				log.Fatalln("[-]Read error:", err)
			}
			break
		}
		if count > 0 {
			output.Write(buf[:count])
		}
	}
	return
}

var browsers = []string{"Chrome", "Firefox", "Safari", "Edge"}
var platforms = []string{"Windows NT 10.0", "Macintosh; Intel Mac OS X 10_15_7", "X11; Ubuntu; Linux x86_64", "iPhone; CPU iPhone OS 14_6 like Mac OS X"}
var browserVersions = map[string][]string{
	"Chrome":  {"91.0.4472.124", "90.0.4430.212", "89.0.4389.114"},
	"Firefox": {"89.0", "88.0", "87.0"},
	"Safari":  {"14.1.1", "14.0.3", "13.1.2"},
	"Edge":    {"91.0.864.59", "90.0.818.56", "89.0.774.68"},
}

func randomChoice(choices []string) string {
	rand.Seed(time.Now().UnixNano())
	return choices[rand.Intn(len(choices))]
}

func randomUserAgent() string {
	browser := randomChoice(browsers)
	platform := randomChoice(platforms)
	version := randomChoice(browserVersions[browser])
	return fmt.Sprintf("Mozilla/5.0 (%s) AppleWebKit/537.36 (KHTML, like Gecko) %s/%s Safari/537.36", platform, browser, version)
}

func iptodomain(ip string) (domain string) {
	// 创建请求
	var url string = "https://ipchaxun.com/" + ip + "/"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return "no"
	}
	// 设置请求头
	ua := randomUserAgent()
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	// 发送请求
	client := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
		Timeout: 10 * time.Second, // 设置请求超时时间
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error making request:", err)
		return "no"
	}
	defer resp.Body.Close()
	//log.Println("site one " + resp.Status)
	// 检查响应状态
	// 解压缩响应体
	var reader io.Reader
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		reader, err = gzip.NewReader(resp.Body)
		if err != nil {
			fmt.Println("Error creating gzip reader:", err)
			return "no"
		}
	default:
		reader = resp.Body
	}
	req.Close = true
	if transport, ok := client.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
	// 读取响应体
	var body bytes.Buffer
	_, err = io.Copy(&body, reader)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return "no"
	}
	// 定义正则表达式
	re := regexp.MustCompile(`<p>\s*<span[^>]*>(?s:.*?)<a\s+href="([^"]+)"\s+target="_blank"[^>]*>([^<]+)</a>`)
	// 使用正则表达式匹配域名
	matches := re.FindStringSubmatch(body.String())
	// 提取并打印域名
	if len(matches) > 2 {
		domain := matches[2]
		return domain
	} else {
		return "no"
	}
}
