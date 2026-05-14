#include <Arduino.h>
#include <WiFi.h>
#include "esp_wifi.h"

void sniffer_callback(void* buff, wifi_promiscuous_pkt_type_t type){
  //preciso que o type seja management
  if(type != WIFI_PKT_MGMT)return;

  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buff; //aponta para a minha struct copia o buff dela todo e joga para um outro ponteiro "*pkt"

  uint8_t *mac_data = pkt->payload; //formatamos um payload original, pegamos um ponteiro de 8 bits e copiamos o payload do pkt para dentro do mac_data

  char len = pkt->rx_ctrl.sig_len;
  char rssi = pkt->rx_ctrl.rssi;
  
  //protecao contra pacotes falhos
  if(len < 22)return;

  uint8_t frame_control = mac_data[0];

  uint8_t *mac_origem = &mac_data[10];

  char ssid[33] = {0};

  if(frame_control == 0x80 || frame_control == 0x40){
    uint8_t ssid_len = mac_data[37];
    if(ssid_len > 0 && ssid_len < 32 && (38 + ssid_len) < len){
      memcpy(ssid, &mac_data[38], ssid_len);
    }
  } else strcpy(ssid, "<OCULTO/BROADCAST>");

  switch (frame_control)
  {
  case 0x80: //beacon
    Serial.printf("[BEACON] SSID: %-20s | ROTEADOR DETECTADO: %02X:%02X:%02X:%02X:%02X:%02X | RSSI: %d\n", ssid, mac_origem[0], mac_origem[1], mac_origem[2], mac_origem[3], mac_origem[4], mac_origem[5], rssi);

    break;
  
  case 0x40: // probe request
    Serial.printf("[PROBE] SSID: %-15s | CELULAR PROCURANDO REDE: %02X:%02X:%02X:%02X:%02X:%02X | RSSI: %d\n", ssid, mac_origem[0], mac_origem[1], mac_origem[2], mac_origem[3], mac_origem[4], mac_origem[5], rssi);
    
    break;

  case 0xC0: // desautenticacao
  case 0xA0: // disassociacao
    Serial.printf("[ALERTA DEAUTH] ATAQUE/DESCONEXÃO: %02X:%02X:%02X:%02X:%02X:%02X\n", mac_origem[0], mac_origem[1], mac_origem[2], mac_origem[3], mac_origem[4], mac_origem[5]);

    break;
  }
  // //verifica se o payload tem tamanho mínimo antes de acessar
  // if (pkt->rx_ctrl.sig_len >= 16) {
  //   Serial.printf("PACOTE CAPTURADO. RSSI: %d | MAC ORIGEM: %02X:%02X:%02X:%02X:%02X:%02X\n", pkt->rx_ctrl.rssi, mac_data[10], mac_data[11], mac_data[12], mac_data[13], mac_data[14], mac_data[15]);
  // }
}

void setup() {
  Serial.begin(115200);
  delay(2000);
  Serial.println("INICIANDO WIShak - MODO PROMISCUO(Sniffer)");

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);

  wifi_promiscuous_filter_t filter;
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
  esp_wifi_set_promiscuous_filter(&filter);

  esp_wifi_set_promiscuous_rx_cb(&sniffer_callback);

  esp_wifi_set_promiscuous(true);

  // esp_wifi_set_channel(6, WIFI_SECOND_CHAN_NONE);
}

void loop() {
  static uint8_t ch = 1;
  esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
  ch = (ch % 13) + 1;
  delay(200);
}

