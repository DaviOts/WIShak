package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/joho/godotenv"
	"go.bug.st/serial"
)

var thingsboardURL string

//o formato que sai do nosso esp32
type ESP32Payload struct {
	Type string `json:"type"`
	MAC  string `json:"mac"`
	SSID string `json:"ssid"`
	RSSI int    `json:"rssi"`
}

//esse formato vai para o thingsboard
type TBPayload struct {
	FrameType   string `json:"frame_type"`
	MAC         string `json:"mac_address"`
	SSID        string `json:"ssid"`
	RSSI        int    `json:"rssi"`
	DeauthCount int    `json:"deauth_count"`
	ProbeCount  int    `json:"probe_count"`
	TotalPPS    int    `json:"total_pps"`
}

var (
	trafegoRede = make(map[string]*TBPayload)
	mu          sync.Mutex
)

func main() {
	
	err := godotenv.Load()
	if err != nil {
		log.Fatal("erro no .env")
	}

	thingsboardToken := os.Getenv("TOKEN_ACESS")
	if thingsboardToken == "" {
		log.Fatal("erro na variavel do token .env")
	}
	thingsboardURL = "http://thingsboard.cloud/api/v1/" + thingsboardToken + "/telemetry"

	modo := &serial.Mode{BaudRate: 115200}
	porta, err := serial.Open("/dev/ttyACM0", modo)
	if err != nil {
		log.Fatal("erro ao abrir porta USB. O ESP32 está plugado? ", err)
	}
	defer porta.Close()

	fmt.Println("[WIShak GATEWAY] Escutando a porta Serial...")

	//roda em paralelo a cada 1 segundo enviando os dados
	go func() {
		for {
			time.Sleep(1 * time.Second)
			enviarParaThingsBoard()
		}
	}()

	//ler as linhas que chegam do esp
	scanner := bufio.NewScanner(porta)
	for scanner.Scan() {
		linha := scanner.Text()

		//so processa se parecer um JSON valido
		if !strings.HasPrefix(linha, "{") {
			continue
		}

		var pkt ESP32Payload
		if err := json.Unmarshal([]byte(linha), &pkt); err == nil {
			processarPacote(pkt)
		}
	}
}

//guarda o pacote na memória RAM de forma segura
func processarPacote(pkt ESP32Payload) {
	mu.Lock()
	defer mu.Unlock()

	//cria o registro base se for um MAC novo neste segundo
	if _, existe := trafegoRede[pkt.MAC]; !existe {
		trafegoRede[pkt.MAC] = &TBPayload{
			MAC:       pkt.MAC,
			RSSI:      pkt.RSSI,
			SSID:      pkt.SSID,
			FrameType: pkt.Type, //assume o tipo do primeiro pacote que chegou
		}
	}

	alvo := trafegoRede[pkt.MAC]
	alvo.TotalPPS++
	
	//mantem o RSSI atualizado com o pacote mais recente
	alvo.RSSI = pkt.RSSI

	//atualiza o SSID apenas se não vier vazio(nome da rede oculto deauth)
	if pkt.SSID != "" {
		alvo.SSID = pkt.SSID
	}

	//hierarquia de Ameaça (DEAUTH > PROBE > BEACON)
	if pkt.Type == "DEAUTH" {
		alvo.DeauthCount++
		alvo.FrameType = "DEAUTH" //o Deauth acaba sendo soberano, sobrescreve qualquer outro tipo
		
	} else if pkt.Type == "PROBE" {
		alvo.ProbeCount++
		if alvo.FrameType != "DEAUTH" {
			alvo.FrameType = "PROBE" //só vira PROBE se não tiver rolado um Deauth nesse segundo
		}
		
	} else if pkt.Type == "BEACON" {
		if alvo.FrameType != "DEAUTH" && alvo.FrameType != "PROBE" {
			alvo.FrameType = "BEACON"
		}
	}
}

//empurra para a nuvem e limpa a memoria
func enviarParaThingsBoard() {
	mu.Lock()
	dadosParaEnviar := trafegoRede
	trafegoRede = make(map[string]*TBPayload) //zera a memoria do segundo
	mu.Unlock()

	//para nao gastar a API da nuvem, caso o ambiente esteja zerado
	if len(dadosParaEnviar) == 0 {
		return
	}

	//cria um "super pacote" que representa o estado geral da rede naquele segundo
	var consolidado TBPayload
	consolidado.RSSI = -100 //começa com o pior sinal possível
	maxScoreAmeaca := -1

	//varre tudo o que o ESP32 escutou
	for mac, payload := range dadosParaEnviar {
		//soma o trafego global da rede
		consolidado.TotalPPS += payload.TotalPPS
		consolidado.DeauthCount += payload.DeauthCount
		consolidado.ProbeCount += payload.ProbeCount

		//logica para mostrar o MAC mais importante da rede, com niveis de prioridades
		score := (payload.DeauthCount * 100) + payload.TotalPPS

		if score > maxScoreAmeaca {
			maxScoreAmeaca = score
			consolidado.MAC = mac
			consolidado.SSID = payload.SSID
			consolidado.FrameType = payload.FrameType
			if payload.RSSI > consolidado.RSSI {
				consolidado.RSSI = payload.RSSI
			}
		}
	}

	//so envia se realmente houve algum trafego
	if consolidado.TotalPPS > 0 {
		jsonData, _ := json.Marshal(consolidado)
		
		resp, err := http.Post(thingsboardURL, "application/json", bytes.NewBuffer(jsonData))
		
		if err != nil {
			fmt.Println("ERRO DE REDE:", err)
		} else {
			//so para mostrar o resumo da rede
			fmt.Printf("NUVEM -> ALVO: %s | PPS: %3d | Deauths: %3d | Status: %s\n", 
			           consolidado.MAC, consolidado.TotalPPS, consolidado.DeauthCount, resp.Status)
			resp.Body.Close()
		}
	}
}