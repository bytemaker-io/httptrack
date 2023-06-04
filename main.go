package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/gopacket"
	"github.com/streadway/amqp"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/gorilla/websocket"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

/*
*
Author:kalean
Time:2023/05/03
*
*/
var (
	upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}
)

type Http struct {
	ID          uint   `gorm:"primaryKey"`
	Time        string `json:"time"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Header      string `json:"header"`
}
type Macaddress struct {
	ID   uint   `gorm:"primaryKey"`
	Mac  string `json:"macaddress"`
	Time string `json:"time"`
}

func handleWebSocket2(gincoon *websocket.Conn) {
	defer gincoon.Close()
	dsn := "root:wf981230@tcp(localhost:3306)/http?charset=utf8mb4&parseTime=True&loc=Local"

	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	db.Table("http").AutoMigrate(&Http{})
	if err != nil {
		log.Fatal(err)
	}

	for {
		conn, err := amqp.Dial("amqp://guest:guest@localhost:5672/")
		if err != nil {
			log.Fatalf("无法连接到RabbitMQ服务器：%v", err)
		}
		defer conn.Close()

		ch, err := conn.Channel()
		if err != nil {
			log.Fatalf("无法创建RabbitMQ通道：%v", err)
		}
		defer ch.Close()

		queueName := "macaddress"
		queue, err := ch.QueueDeclare(
			queueName,
			false,
			false,
			false,
			false,
			nil,
		)
		if err != nil {
			log.Fatalf("无法声明RabbitMQ队列：%v", err)
		}

		// 消费消息
		msgs, err := ch.Consume(
			queue.Name,
			"",    // 消费者标识符（为空表示由RabbitMQ生成）
			true,  // 自动应答
			false, // 是否独占
			false, // 是否阻塞等待
			false, // 额外属性
			nil,   // 其他参数
		)
		if err != nil {
			log.Fatalf("无法注册RabbitMQ消费者：%v", err)
		}

		// 循环读取消息
		forever := make(chan bool)

		go func() {
			for msg := range msgs {
				// 处理接收到的消息

				reply := []byte(string(msg.Body))
				var macaddress Macaddress
				err := json.Unmarshal(msg.Body, &macaddress)
				db.Table("mac").Create(&macaddress)
				err = gincoon.WriteMessage(websocket.TextMessage, reply)
				if err != nil {
					log.Println("Failed to send reply to WebSocket:", err)
					break
				}
			}
		}()

		fmt.Println("等待接收消息...")
		<-forever
	}

}
func main() {

	router := gin.Default()
	router.Static("/static", "./static")
	// 路由参数
	router.GET("/ws2", func(c *gin.Context) {
		gincoon, err := upgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			log.Println("Failed to upgrade to WebSocket:", err)
			return
		}

		// 在此处处理WebSocket连接
		go handleWebSocket2(gincoon)

	})
	router.GET("/ws", func(c *gin.Context) {
		gincoon, err := upgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			log.Println("Failed to upgrade to WebSocket:", err)
			return
		}

		// 在此处处理WebSocket连接
		go handleWebSocket(gincoon)
	})

	err := router.Run(":9090")
	if err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
func handleWebSocket(gincoon *websocket.Conn) {
	defer gincoon.Close()
	for {
		host := "192.168.1.1"
		port := 22
		user := "root"
		password := "wf981230"
		dsn := "root:wf981230@tcp(localhost:3306)/http?charset=utf8mb4&parseTime=True&loc=Local"

		db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
		db.Table("http").AutoMigrate(&Http{})

		if err != nil {
			log.Fatal(err)
		}

		// 程序结束前关闭数据库连接
		sqlDB, err := db.DB()
		if err != nil {
			log.Fatal(err)
		}
		defer sqlDB.Close()
		//
		// 创建SSH客户端配置
		config := &ssh.ClientConfig{
			User: user,
			Auth: []ssh.AuthMethod{
				ssh.Password(password),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}
		//死循环
		for {
			conn, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, port), config)
			if err != nil {
				panic(fmt.Sprintf("Failed to connect to SSH server: %s", err))
			}
			defer conn.Close()
			session, err := conn.NewSession()
			if err != nil {
				panic(fmt.Sprintf("Failed to create SSH session: %s", err))
			}
			defer session.Close()
			// 创建SFTP会话
			sftpClient, err := sftp.NewClient(conn)
			if err != nil {
				panic(fmt.Sprintf("Failed to open SFTP session: %s", err))
			}
			defer sftpClient.Close()

			command := "tcpdump -i any -s 0 -w http.pcap port 80"
			err = session.Start(command)
			if err != nil {
				log.Fatalf("Failed to execute comman11d: %v", err)
			}
			//等待10秒
			time.Sleep(10 * time.Second)
			session2, err := conn.NewSession()
			if err != nil {
				panic(fmt.Sprintf("Failed to create SSH session: %s", err))
			}
			defer session2.Close()
			if err != nil {
				panic(fmt.Sprintf("Failed to create SSH session: %s", err))
			}
			command = "ps | grep tcpdump | grep -v grep | awk '{print $1}' | xargs kill"
			err = session2.Run(command)
			if err != nil {
				log.Fatalf("Failed to execute comman111d: %v", err)
			}
			// 打开远程文件

			remoteFilePath := "/root/http.pcap"
			remoteFile, err := sftpClient.Open(remoteFilePath)
			if err != nil {
				panic(fmt.Sprintf("Failed to open remote file: %s", err))
			}
			defer remoteFile.Close()

			localFilePath := "http.pcap"
			localFile, err := os.Create(localFilePath)
			if err != nil {
				panic(fmt.Sprintf("Failed to create local file: %s", err))
			}
			defer localFile.Close()

			// 将远程文件内容复制到本地文件
			_, err = io.Copy(localFile, remoteFile)
			if err != nil {
				panic(fmt.Sprintf("Failed to copy file: %s", err))
			}

			fmt.Println("File copied successfully!")
			// 判断本地文件是否为空
			fileInfo, err := localFile.Stat()
			if err != nil {
				continue
			}
			if fileInfo.Size() == 0 {
				fmt.Println("File is empty!")
				continue
			}

			handle, err := pcap.OpenOffline("http.pcap")
			if err != nil {
				log.Fatal(err)
			}
			defer handle.Close()

			err = handle.SetBPFFilter("tcp port 80")
			if err != nil {
				log.Fatal(err)
			}

			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			for packet := range packetSource.Packets() {
				applicationLayer := packet.ApplicationLayer()
				if applicationLayer != nil {
					timestamp := time.Now().Unix()
					timestampStr := strconv.FormatInt(timestamp, 10)
					// 获取HTTP请求头
					httpHeaders := gopacket.Payload(applicationLayer.Payload())
					a := string(httpHeaders)
					//将a转为utf-8
					a = string([]byte(a))
					fmt.Println(a)

					//创建对象
					ipLayer := packet.Layer(layers.LayerTypeIPv4)
					if ipLayer == nil {
						continue
					}
					ipPacket, _ := ipLayer.(*layers.IPv4)

					destinationIP := ipPacket.DstIP.String()
					http := Http{
						Header:      a,
						Destination: destinationIP,
						Source:      ipPacket.SrcIP.String(),
						Time:        timestampStr,
					}
					db.Table("http").Create(&http)
					jsonData, err := json.Marshal(http)
					fmt.Println(jsonData)
					if err != nil {
						log.Fatal("Failed to marshal JSON:", err)
					}
					reply := []byte(string(jsonData))
					err = gincoon.WriteMessage(websocket.TextMessage, reply)
					if err != nil {
						log.Println("Failed to send reply to WebSocket:", err)
						break
					}
				}
			}

		}

	}

}
