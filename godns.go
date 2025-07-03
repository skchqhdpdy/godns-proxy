package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

type Config struct {
	MysqlDSN          string `json:"mysqlDSN"`
	DiscordWebhookURL string `json:"discordWebhookURL"`
	RemoteAddr        string `json:"remoteAddr"`
	LocalAddr         string `json:"localAddr"`
}

var defaultConfig = Config{
	MysqlDSN:          "user:password@tcp(localhost:3306)/godns",
	DiscordWebhookURL: "your_webhook_url",
	RemoteAddr:        "aodd.xyz:53",
	LocalAddr:         "ns1.aodd.xyz",
}

var configFilePath string = getConfigPath()
var config Config = loadConfig()
var localPort = ":53"
var db *sql.DB

func BlockIP(IP string, reason string) {
	var blocked int
	var BR sql.NullString
	db.QueryRow("SELECT blocked, memo FROM ips WHERE ip = ?", IP).Scan(&blocked, &BR)

	if blocked == 1 {
		fmt.Printf("IP %s 는 이미 차단된 상태입니다 (사유: %s)\n", IP, BR.String)
		return
	}

	var memo interface{}
	if reason == "" {
		memo = nil
	} else {
		memo = reason
	}

	query := `
	INSERT INTO ips (ip, memo, server, count, last_seen, blocked)
	VALUES (?, ?, ?, 1, ?, 1)
	ON DUPLICATE KEY UPDATE
		memo = VALUES(memo),
		server = VALUES(server),
		last_seen = VALUES(last_seen),
		blocked = VALUES(blocked)
	`
	_, err := db.Exec(query, IP, memo, config.LocalAddr, time.Now().Unix())
	if err != nil {
		log.Printf("IP 차단/업데이트 실패: %v", err)
		return
	}
	fmt.Printf("IP %s 차단됨 (사유: %v)\n", IP, reason)
}
func UnblockIP(IP string) {
	var BR sql.NullString
	db.QueryRow("SELECT memo FROM ips WHERE ip = ? AND blocked = 1", IP).Scan(&BR)

	query := `UPDATE ips SET blocked = 0, last_seen = ?, memo = NULL WHERE IP = ? AND blocked = 1`
	res, err := db.Exec(query, time.Now().Unix(), IP)
	if err != nil {
		log.Printf("IP 해제 실패: %v", err)
		return
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		fmt.Printf("IP %s 는 차단된 상태가 아닙니다\n", IP)
	} else {
		fmt.Printf("IP %s 해제됨 (기존 차단 사유: %s)\n", IP, BR.String)
	}
}
func DeleteIP(IP string) {
	var BR sql.NullString
	db.QueryRow("SELECT memo FROM ips WHERE ip = ?", IP).Scan(&BR)

	query := `DELETE FROM ips WHERE ip = ?`
	res, err := db.Exec(query, IP)
	if err != nil {
		log.Printf("IP 삭제 실패: %v", err)
		return
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		fmt.Printf("IP %s 는 존재하지 않습니다\n", IP)
	} else {
		fmt.Printf("IP %s 삭제됨 (기존 메모: %s)\n", IP, BR.String)
	}
}
func ShowIP(IP string) {
	var id, count, blocked, lastSeen int64
	var server, memo sql.NullString

	err := db.QueryRow("SELECT id, memo, server, count, Last_seen, blocked FROM ips WHERE ip = ?", IP).
		Scan(&id, &memo, &server, &count, &lastSeen, &blocked)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Printf("IP %s 정보가 없습니다.\n", IP)
			return
		}
		log.Printf("DB 조회 오류: %v\n", err)
		return
	}

	// lastSeen을 사용자 로컬 타임존 시간으로 변환
	t := time.Unix(lastSeen, 0).In(time.Local)
	formattedTime := t.Format("2006-01-02 15:04:05 MST")

	fmt.Printf(
		"id: %d, IP: %s, memo: %s, server: %s, count: %d, Last_seen: %s(%d), blocked: %d\n",
		id, IP, memo.String, server.String, count, formattedTime, lastSeen, blocked,
	)
}
func RecentIP(column string, limit string) {
	query := fmt.Sprintf(
		"SELECT id, IP, memo, server, count, Last_seen, blocked FROM ips ORDER BY %s DESC LIMIT %s",
		column, limit,
	)

	rows, err := db.Query(query)
	if err != nil {
		log.Printf("DB 쿼리 오류: %v\n", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var id, count, blocked, lastSeen int64
		var IP, server, memo sql.NullString

		err := rows.Scan(&id, &IP, &memo, &server, &count, &lastSeen, &blocked)
		if err != nil {
			log.Printf("행 스캔 실패: %v\n", err)
			continue
		}

		t := time.Unix(lastSeen, 0).In(time.Local)
		formattedTime := t.Format("2006-01-02 15:04:05 MST")

		fmt.Printf(
			"id: %d, IP: %s, memo: %s, server: %s, count: %d, Last_seen: %s(%d), blocked: %d\n",
			id, IP.String, memo.String, server.String, count, formattedTime, lastSeen, blocked,
		)
	}
}
func IsIPBlocked(IP string) bool {
	var blocked int
	err := db.QueryRow("SELECT blocked FROM ips WHERE IP = ?", IP).Scan(&blocked)
	if err != nil {
		if err != sql.ErrNoRows {
			log.Printf("IP 차단 상태 조회 실패: %v", err)
		}
		blocked = 0
	}

	query := `
	INSERT INTO ips (IP, server, count, last_seen)
	VALUES (?, ?, 1, ?)
	ON DUPLICATE KEY UPDATE
		count = count + 1,
		last_seen = VALUES(last_seen)
	`
	_, err = db.Exec(query, IP, config.LocalAddr, time.Now().Unix())
	if err != nil {
		log.Printf("IP 정보 로깅 실패: %v", err)
	}
	return blocked == 1
}
func RefusedResponse(req []byte) []byte {
	if len(req) < 12 {
		return nil
	}
	res := make([]byte, len(req))
	copy(res, req)
	res[2] |= 0x80
	res[2] &^= 0x70
	res[3] = 0x05
	for i := 6; i < 12; i++ {
		res[i] = 0
	}
	return res
}

func initDB() {
	var err error
	dsn := config.MysqlDSN
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("DB 연결 실패: %v", err)
	}
	if err := db.Ping(); err != nil {
		log.Fatalf("DB Ping 실패: %v", err)
	}
	log.Println("MySQL 연결 성공")
}

func init() {
	ensureRoot()
	if len(os.Args) == 1 || os.Args[1] != "-config" {
		initDB()
	}
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-h":
			log.Print(
				"사용법:\n" +
					"    -config\n" +
					"    -ban <IP> [Reason]\n" +
					"    -unban <IP>\n" +
					"    -del <IP>\n" +
					"    -show <IP>\n" +
					"    -recent <DB_column> <Amount>\n")
			return
		case "-config":
			editConfigFile()
			return
		case "-ban":
			if len(os.Args) < 3 {
				fmt.Println("사용법: -ban <IP> [Reason]")
				return
			}
			memo := ""
			if len(os.Args) > 3 {
				memo = strings.Join(os.Args[3:], " ")
			}
			BlockIP(os.Args[2], memo)
			return
		case "-unban":
			if len(os.Args) < 3 {
				fmt.Println("사용법: -unban <IP>")
				return
			}
			UnblockIP(os.Args[2])
			return
		case "-del":
			if len(os.Args) < 3 {
				fmt.Println("사용법: -del <IP>")
				return
			}
			DeleteIP(os.Args[2])
			return
		case "-show":
			if len(os.Args) < 3 {
				fmt.Println("사용법: -show <IP>")
				return
			}
			ShowIP(os.Args[2])
			return
		case "-recent":
			if len(os.Args) < 4 {
				fmt.Println("사용법: -recent <DB_column> <Amount>")
				return
			}
			RecentIP(os.Args[2], os.Args[3])
			return
		}
	}

	go startTCPForwarding(config) //TCP 포워딩 시작
	startUDPForwarding(config)    //UDP 포워딩 시작
}

func startTCPForwarding(config Config) {
	listener, err := net.Listen("tcp", localPort)
	if err != nil {
		log.Printf("TCP 포트 %s에서 리스닝 실패: %v", localPort, err)
		pauseConsole()
		return
	}
	defer listener.Close()

	log.Printf("TCP 포워딩 시작: %s -> %s", config.LocalAddr+localPort, config.RemoteAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("TCP 연결 수락 실패: %v", err)
			continue
		}
		go handleTCPConnection(conn, config)
	}
}

func handleTCPConnection(localConn net.Conn, config Config) {
	defer localConn.Close()

	remoteIP, _, _ := net.SplitHostPort(localConn.RemoteAddr().String())
	if IsIPBlocked(remoteIP) {
		log.Printf("차단된 IP TCP 패킷 차단: %s", remoteIP)

		buf := make([]byte, 4096)
		_, err := io.ReadFull(localConn, buf[:2])
		if err != nil {
			log.Printf("TCP 차단 응답 읽기 실패: %v", err)
			return
		}
		packetLen := int(buf[0])<<8 | int(buf[1])
		if packetLen > len(buf)-2 {
			log.Printf("TCP 차단 패킷 크기 초과")
			return
		}
		_, err = io.ReadFull(localConn, buf[2:2+packetLen])
		if err != nil {
			log.Printf("TCP 차단 응답 DNS 패킷 읽기 실패: %v", err)
			return
		}
		resp := RefusedResponse(buf[2 : 2+packetLen])
		if resp == nil {
			return
		}
		respWithLen := make([]byte, 2+len(resp))
		respWithLen[0] = byte(len(resp) >> 8)
		respWithLen[1] = byte(len(resp))
		copy(respWithLen[2:], resp)
		_, err = localConn.Write(respWithLen)
		if err != nil {
			log.Printf("TCP 차단 응답 전송 실패: %v", err)
		}
		return
	}

	remoteConn, err := net.Dial("tcp", config.RemoteAddr)
	if err != nil {
		log.Printf("원격 TCP 서버 연결 실패: %v", err)
		return
	}
	defer remoteConn.Close()

	log.Printf("TCP 연결됨: %s -> %s -> %s | %d", localConn.RemoteAddr(), config.LocalAddr+localPort, config.RemoteAddr, time.Now().Unix())
	go sendToDiscord(fmt.Sprintf("TCP 연결됨: %s -> %s -> %s | <t:%d:F>", localConn.RemoteAddr(), config.LocalAddr+localPort, config.RemoteAddr, time.Now().Unix()))

	go io.Copy(remoteConn, localConn)
	io.Copy(localConn, remoteConn)
}

func startUDPForwarding(config Config) {
	localAddr, err := net.ResolveUDPAddr("udp", localPort)
	if err != nil {
		log.Fatalf("로컬 UDP 주소 오류: %v", err)
	}
	remoteAddr, err := net.ResolveUDPAddr("udp", config.RemoteAddr)
	if err != nil {
		log.Fatalf("원격 UDP 주소 오류: %v", err)
	}

	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		log.Fatalf("UDP 포트 %s 리스닝 실패: %v", localPort, err)
	}
	defer conn.Close()

	log.Printf("UDP 포워딩 시작: %s -> %s", config.LocalAddr+localPort, config.RemoteAddr)

	buf := make([]byte, 65535)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("UDP 읽기 오류: %v", err)
			continue
		}

		go func(data []byte, addr *net.UDPAddr) {
			remoteIP := clientAddr.IP.String()
			if IsIPBlocked(remoteIP) {
				log.Printf("차단된 IP UDP 패킷 차단: %s", remoteIP)

				refusedResp := RefusedResponse(buf[:n])
				if refusedResp != nil {
					_, err := conn.WriteToUDP(refusedResp, clientAddr)
					if err != nil {
						log.Printf("UDP 차단 응답 전송 실패: %v", err)
					}
				}
				return
			}

			remoteConn, err := net.DialUDP("udp", nil, remoteAddr)
			if err != nil {
				log.Printf("UDP 원격 연결 실패: %v", err)
				return
			}
			defer remoteConn.Close()

			log.Printf("UDP 연결됨: %s -> %s -> %s | %d", addr, config.LocalAddr+localPort, config.RemoteAddr, time.Now().Unix())
			go sendToDiscord(fmt.Sprintf("UDP 연결됨: %s -> %s -> %s | <t:%d:F>", addr, config.LocalAddr+localPort, config.RemoteAddr, time.Now().Unix()))

			_, err = remoteConn.Write(data)
			if err != nil {
				log.Printf("UDP 쓰기 실패: %v", err)
				return
			}

			remoteConn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, _, err := remoteConn.ReadFrom(buf)
			if err != nil {
				log.Printf("UDP 응답 없음 또는 읽기 실패: %v", err)
				return
			}

			conn.WriteToUDP(buf[:n], addr)
		}(buf[:n], clientAddr)
	}
}

func sendToDiscord(message string) {
	payload := map[string]string{"content": message}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Discord 메시지 전송 실패: %v", err)
		return
	}

	_, err = http.Post(config.DiscordWebhookURL, "application/json", bytes.NewReader(payloadBytes))
	if err != nil {
		log.Printf("Discord 웹훅 요청 실패: %v", err)
	}
}

func ensureRoot() {
	if runtime.GOOS == "windows" {

	} else {
		if os.Geteuid() != 0 {
			log.Fatalln("이 프로그램은 sudo 또는 관리자 권한으로 실행되어야 합니다.")
		}
	}
}

func loadConfig() Config {
	if _, err := os.Stat(configFilePath); os.IsNotExist(err) {
		log.Printf("설정 파일 없음. 기본 설정 파일을 생성합니다: %s", configFilePath)
		file, err := os.Create(configFilePath)
		if err != nil {
			log.Fatalf("설정 파일 생성 실패: %v", err)
		}
		defer file.Close()

		configData, err := json.MarshalIndent(defaultConfig, "", "  ")
		if err != nil {
			log.Fatalf("설정 파일 데이터 생성 실패: %v", err)
		}
		file.Write(configData)
		return defaultConfig
	}

	file, err := os.Open(configFilePath)
	if err != nil {
		log.Fatalf("설정 파일 열기 실패: %v", err)
	}
	defer file.Close()

	var config Config
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		log.Fatalf("설정 파일 읽기 실패: %v", err)
	}
	return config
}

func getConfigPath() string {
	var configFilePath string
	if runtime.GOOS == "windows" {
		configFilePath = `C:\godns\configGodns.json`
	} else {
		configFilePath = "/etc/godns/configGodns.json"
	}
	dir := filepath.Dir(configFilePath)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err := os.MkdirAll(dir, 0755)
		if err != nil {
			log.Fatalf("설정 디렉토리 생성 실패: %v", err)
		}
	}
	return configFilePath
}

func editConfigFile() {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("notepad", configFilePath)
	} else {
		editor := os.Getenv("editor")
		if editor == "" {
			editor = "vim" //기본값
		}
		cmd = exec.Command("sudo", editor, configFilePath)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	err := cmd.Run()
	if err != nil {
		log.Fatalf("설정 파일 편집기 실행 실패: %v", err)
	}
}

func pauseConsole() {
	fmt.Println("\nPress Enter to exit...")
	fmt.Scanln()
}
