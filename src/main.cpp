#include <Arduino.h>
#include <WiFi.h>
#include "esp_wifi.h"

/**
 * Função de Callback para o Modo Promíscuo (Sniffer)
 * É disparada pelo hardware do ESP32 toda vez que um pacote Wi-Fi é capturado no ar
 * * @param buff Ponteiro para os dados brutos do pacote capturado
 * @param type Tipo do pacote capturado (Dados, Gerenciamento, Controle, etc)
 */
void sniffer_callback(void* buff, wifi_promiscuous_pkt_type_t type){
  //aplica um filtro de interesse apenas nos quadros de Gerenciamento (Management Frames)
  if(type != WIFI_PKT_MGMT) return;

  //realiza o cast do buffer para a estrutura padrão de pacotes promíscuos do ESP32
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buff;
  //mac_data aponta para o início do cabeçalho MAC do frame 802.11 (Payload do pacote capturado)
  uint8_t *mac_data = pkt->payload;

  //extrai metadados de rádio calculados pelo hardware do chip
  char len = pkt->rx_ctrl.sig_len; //comprimento total do sinal do pacote em bytes
  int8_t rssi = pkt->rx_ctrl.rssi; //intensidade do sinal recebido (dBm)

  //validaçao para quadros de gerenciamento que possuem 22 bytes de cabeçalho(minimo)
  if(len < 22) return;

  //o primeiro byte do cabeçalho 802.11 contém o Frame Control
  uint8_t frame_control = mac_data[0];
  //no padrao IEEE 802.11, o endereço MAC de Origem inicia no offset de memória 10
  uint8_t *mac_origem = &mac_data[10];

  //buffer para armazenar o nome da rede (SSID), limitado ao padrão de 32 caracteres + caractere nulo
  char ssid[33] = {0};

  //extrai o SSID se for Beacon ou Probe
  if(frame_control == 0x80 || frame_control == 0x40){
    //no cabeçalho offset 37 indica o comprimento do campo SSID
    uint8_t ssid_len = mac_data[37];
    //validaçao de integridade para evitar um overflow no buffer
    if(ssid_len > 0 && ssid_len < 32 && (38 + ssid_len) < len){
      //o SSID começa no offset 38
      memcpy(ssid, &mac_data[38], ssid_len);
    }
  }

  //imprime o JSON puro diretamente no serial port
  switch (frame_control)
  {
  case 0x80: // BEACON(quadros de anuncio emitidos por pontos de acesso que sao roteadores)
    Serial.printf("{\"type\":\"BEACON\", \"mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\", \"ssid\":\"%s\", \"rssi\":%d}\n", 
                  mac_origem[0], mac_origem[1], mac_origem[2], mac_origem[3], mac_origem[4], mac_origem[5], ssid, rssi);
    break;
  
  case 0x40: // PROBE(dispositivos que buscam redes)
    Serial.printf("{\"type\":\"PROBE\", \"mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\", \"ssid\":\"%s\", \"rssi\":%d}\n", 
                  mac_origem[0], mac_origem[1], mac_origem[2], mac_origem[3], mac_origem[4], mac_origem[5], ssid, rssi);
    break;

  case 0xC0: // DEAUTH(um comando de desconexao, atques DoS de rede)
  case 0xA0: // DISASSOCIATION(comando de encerramento de associação)
    Serial.printf("{\"type\":\"DEAUTH\", \"mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\", \"ssid\":\"%s\", \"rssi\":%d}\n", 
                  mac_origem[0], mac_origem[1], mac_origem[2], mac_origem[3], mac_origem[4], mac_origem[5], ssid, rssi);
    break;
  }
}

void setup() {
  Serial.begin(115200);
  delay(2000);

  //configura a interface wifi para o modo cliente e desconecta de qualquer rede ativa
  //isso libera o hardware de rádio para o modo promíscuo
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);

  //configuração dos filtros de hardware do SDK nativo da Espressif (esp_wifi)
  wifi_promiscuous_filter_t filter;
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT; // Filtra estritamente a camada de Gerenciamento

  esp_wifi_set_promiscuous_filter(&filter); //aplica o filtro estruturado
  esp_wifi_set_promiscuous_rx_cb(&sniffer_callback); //define a funçao de callback para o tratamento dos dados
  esp_wifi_set_promiscuous(true); //habilita o modo promíscuo de rádio
}

//salto de canais para varredura
void loop()
{
  static uint8_t ch = 1;
  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
  ch = (ch % 13) + 1;
  delay(200);
}