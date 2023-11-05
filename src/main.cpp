/*
__   _____ ___ ___        Author: Vincent BESSON
 \ \ / /_ _| _ ) _ \      Release: 0.35
  \ V / | || _ \   /      Date: 20221227
   \_/ |___|___/_|_\      Description: Interface Linky MQTT with NRF24 Gazpar vers HA
                2022      Licence: Creative Commons
______________________

Release changelog:
  +20230416: Make it with ESP32 AZDELIVERY V4 working
  +20221228: False positive, remove gazvol 0 value, add payload log for investigation
  +20221227: Instability, changing String to char
*/ 

#include <SPI.h>
//#include <Time.h>

#include <WiFi.h>
#include <Wire.h>

#include <PubSubClient.h>
#include <Adafruit_SleepyDog.h>

#include <ArduinoJson.h>
#include <LibTeleinfo.h>

#include <RF24.h>
#include "pwd.h"

#include <WiFiUdp.h>

#include "RemoteDebug.h"
#include <ArduinoOTA.h>
#include <ESPmDNS.h>
#include "time.h"

#include <CircularBuffer.h>


/*********************************/
#define DEBUG_ENV
/**********************************/

#ifdef DEBUG_ENV
#define __FORMAT(FORMAT) "(%s:%d) " FORMAT
#define LOGD(TAG, FORMAT, ...) ESP_LOGD(TAG, __FORMAT(FORMAT), __func__, __LINE__, ##__VA_ARGS__); debugD(__FORMAT(FORMAT), __func__, __LINE__, ##__VA_ARGS__);
#define LOGI(TAG, FORMAT, ...) ESP_LOGI(TAG, __FORMAT(FORMAT), __func__, __LINE__, ##__VA_ARGS__); debugI(__FORMAT(FORMAT), __func__, __LINE__, ##__VA_ARGS__);
#define LOGW(TAG, FORMAT, ...) ESP_LOGW(TAG, __FORMAT(FORMAT), __func__, __LINE__, ##__VA_ARGS__); debugW(__FORMAT(FORMAT), __func__, __LINE__, ##__VA_ARGS__);
#define LOGE(TAG, FORMAT, ...) ESP_LOGE(TAG, __FORMAT(FORMAT), __func__, __LINE__, ##__VA_ARGS__); debugE(__FORMAT(FORMAT), __func__, __LINE__, ##__VA_ARGS__);
#endif

#ifndef DEBUG_ENV
#define LOGD(TAG, FORMAT, ...) ;
#define LOGI(TAG, FORMAT, ...) ;
#define LOGW(TAG, FORMAT, ...) ;
#define LOGE(TAG, FORMAT, ...) ;
#endif


static const char * DISCOVERY_WIFI_SSID_TOPIC=              "homeassistant/sensor/ESP32_LINKY_GAZPAR/wifi_ssid/config";
static const char * DISCOVERY_WIFI_RSSI_TOPIC=              "homeassistant/sensor/ESP32_LINKY_GAZPAR/wifi_rssi/config";
static const char * DISCOVERY_IP_ADDR_TOPIC=                "homeassistant/sensor/ESP32_LINKY_GAZPAR/ip_addr/config";
static const char * DISCOVERY_MAC_ADDR_TOPIC=               "homeassistant/sensor/ESP32_LINKY_GAZPAR/mac_addr/config";
static const char * DISCOVERY_PING_ALIVE_TOPIC=             "homeassistant/sensor/ESP32_LINKY_GAZPAR/ping_alive/config";
static const char * WIFI_SSID_STATE_TOPIC =                 "homeassistant/ESP32_LINKY_GAZPAR/wifi_ssid/state";
static const char * WIFI_RSSI_STATE_TOPIC =                 "homeassistant/ESP32_LINKY_GAZPAR/wifi_rssi/state";
static const char * IP_ADDR_STATE_TOPIC =                   "homeassistant/ESP32_LINKY_GAZPAR/ip_addr/state";
static const char * MAC_ADDR_STATE_TOPIC =                  "homeassistant/ESP32_LINKY_GAZPAR/mac_addr/state";
static const char * PING_ALIVE_STATE_TOPIC =                "homeassistant/ESP32_LINKY_GAZPAR/ping_alive/state";
#if CRYPTO==1
//#include <Base64.h>                   // https://github.com/agdl/Base64
#include <AES.h>                        // https://forum.arduino.cc/index.php?topic=88890.0
AES aes ;
uint8_t key128bits[] = AES_KEY;         // KEEP SECRET !
const uint8_t iv128bits[]  = AES_IV;    // NO NEED TO KEEP SECRET
#endif

const uint16_t maxMessageSize = 32;     // message size + 1 NEEDS to be a multiple of N_BLOCK (16)

TInfo          tinfo; // Teleinfo object

static const char* ntpServer = "fr.pool.ntp.org";
static const long  gmtOffset_sec = 3600;
static const int   daylightOffset_sec = 3600;

static const char * MQTT_DEVICENAME="ESP32_LINKY_GAZPAR";
float pingAliveCount=0;

unsigned long lastUpdateDiag = 0;
const unsigned long UpdateDiagInterval_ms = 60 * 1000;

const char * fwVersion="0.35";

WiFiClient wifiClient;
PubSubClient client(wifiClient);

int status = WL_IDLE_STATUS;

unsigned long newTS;
unsigned long va_lastValueTS=0;
unsigned long kWh_lastValueTS=0;

int kWh_oldValue=0;
int va_oldValue=0;

double gazvol_oldValue=0;

int reboot_counter=0;
int wifi_disconnect_counter=0;

/*  Configuration variable */

const int wifi_disconnect_threshold=12;
const int reboot_threshold=6;
const int linky_va_variation_threshold_report=10;
const int linky_report_interval=180; /* 180 sec */

#define pinRadioPwr   33 
#define pinCE   32                // On associe la broche "CE" du NRF24L01 à la sortie digitale D7 de l'arduino
#define pinCSN  25                // On associe la broche "CSN" du NRF24L01 à la sortie digitale D8 de l'arduino
#define tunnel  "D6E1A"           // On définit le "nom de tunnel" (5 caractères) à travers lequel on va recevoir les données de l'émetteur

#define RXD2 16
#define TXD2 17

const byte adresse[6] = tunnel;       // Mise au format "byte array" du nom du tunnel
char message[64];                     // Avec cette librairie, on est "limité" à 32 caractères par message

RF24 radio(pinCE, pinCSN);    // Instanciation du NRF24L01

#define RADIO_ON  1
#define TELEINFO_ON  1

CircularBuffer<void*, 100> cLog;

WiFiServer server(80);

RemoteDebug Debug;

/*************** FUNCTION DECLARATION ************************************/

void connectMQTT();

char * getValue_c(char * data, char *sep, char *key);
const char* encode_128bits(const char* texteEnClair);
const char* decode_128bits(const char* texteEnBase64,int len);


//void debughex(const char * message,int len);
void DataCallback(ValueList * me, uint8_t  flags);

void sendMQTTUpdate(const char rootTopic[],double value);
void sendMQTTUpdateStr(const char rootTopic[],char  * value);

void printWiFiData();
void addCircularLog(char * event);

void sendMQTTEnergyVADiscoveryMsg();
void sendMQTTEnergyKwHDiscoveryMsg();
void sendMQTTEnergyGazM3DiscoveryMsg();
void sendMQTTBatteryDiscoveryMsg();
void sendMQTTPayloadErrorDiscoveryMsg();

void MQTT_DiscoveryMsg_Text_WIFI_SSID();
void MQTT_DiscoveryMsg_Text_WIFI_RSSI();
void MQTT_DiscoveryMsg_Text_IpAddr();
void MQTT_DiscoveryMsg_Text_MacAddr();
void MQTT_DiscoveryMsg_Text_PingAlive();

void updateDataDiag();

/************ Global State (you don't need to change this!) ******************/

//const char deviceName[] = "WINC 1500 Linky1"; 
//const char deviceID[] = "WINC1500_LINKY_1"; 
void software_Reboot(){
  /*int countdownMS =*/ Watchdog.enable(10);
}
#if CRYPTO==1
const char* encode_128bits(const char* texteEnClair) {

  // static allocation of buffers to ensure the stick around when returning from the function until the next call
  static uint8_t message[maxMessageSize];
  static uint8_t cryptedMessage[maxMessageSize];

  uint8_t iv[N_BLOCK]; // memory is modified during the call
  memcpy(iv, iv128bits, N_BLOCK);

  memset(message, 0, maxMessageSize); // padding with 0
  memset(cryptedMessage, 0, maxMessageSize); // padding with 0

  uint16_t tailleTexteEnClair = strlen(texteEnClair) + 1; // we grab the trailing NULL char for encoding
  memcpy(message, texteEnClair, tailleTexteEnClair);

  if ((tailleTexteEnClair % N_BLOCK) != 0) tailleTexteEnClair = N_BLOCK * ((tailleTexteEnClair / N_BLOCK) + 1);
  int n_block = tailleTexteEnClair / N_BLOCK;

  aes.set_key(key128bits, 128);
  aes.cbc_encrypt(message, cryptedMessage, n_block, iv); // iv will be modified
  aes.clean();

  return (char*)cryptedMessage;
}
#endif

/*
void debughex(const char * message,int len){
  int c;
  for (int n = 0; n <= len; n++){
    c=message[n];
    GG_DEBUG_PRINT("0x");
    GG_DEBUG_PRINT(c < 16 ? "0" : "");
    GG_DEBUG_PRINTHEX(c);
    GG_DEBUG_PRINT(" ");
  }
   GG_DEBUG_PRINTLN(" ");
}

*/

#if CRYPTO==1
const char* decode_128bits(const char* texteEnBase64,int len){
  // static allocation of buffers to ensure the stick around when returning from the function until the next call
  static uint8_t message[maxMessageSize];
  static uint8_t cryptedMessage[maxMessageSize];

  uint8_t iv[N_BLOCK]; // memory is modified during the call
  memcpy(iv, iv128bits, N_BLOCK);

  
  memset(cryptedMessage, 0, maxMessageSize); // padding with 0

  int n_block=len/ N_BLOCK;
  GG_DEBUG_PRINT("len:");
  GG_DEBUG_PRINTLN(len);
  GG_DEBUG_PRINT("n_block:");
  GG_DEBUG_PRINTLN(n_block);

  aes.set_key(key128bits, 128);
  aes.cbc_decrypt((byte *)texteEnBase64, message, n_block, iv); // iv will be modified
  aes.clean();

  return (char*) message;
}
#endif


/* ======================================================================
Function: DataCallback 
Purpose : callback when we detected new or modified data received
Input   : linked list pointer on the concerned data
          current flags value
Output  : - 
Comments: -
====================================================================== */
void DataCallback(ValueList * me, uint8_t  flags){

  float value=0;
  if (flags & TINFO_FLAGS_ADDED)
    LOGD("TINFO","TeleInfo [NEW] key:%s, value:%s",me->name,me->value);

  if (flags & TINFO_FLAGS_UPDATED)
    LOGD("TINFO","TeleInfo [UPD] key:%s, value:%s",me->name,me->value);

  newTS= millis();
  
  if (!strcmp(me->name,"BASE")){
    value=roundf((atof(me->value))*100.0)/100.0;
    LOGD("TINFO","TeleInfo new [BASE] value:%.2f",value);
    if ((newTS-kWh_lastValueTS)/1000>linky_report_interval){
      float val_f=value/1000; // We are reporting kWh not Wh
      LOGD("TINFO","TeleInfo new [BASE] value:%.2f send to MQTT",val_f);
      sendMQTTUpdate("/energy_kwh/state",val_f);
      kWh_lastValueTS=newTS;
      kWh_oldValue=value;
      return;
    }
  }

  if (!strcmp(me->name,"PAPP")){
    
    value=roundf((atof(me->value))*100.0)/100.0;
    LOGD("TINFO","TeleInfo new [PAPP] value:%.2f",value);

    if ((newTS-va_lastValueTS)/1000>linky_report_interval){
      LOGD("TINFO","TeleInfo new [PAPP] value:%.2f send to MQTT",value);
      sendMQTTUpdate("/energy_va/state",value);
      va_oldValue=value;
      va_lastValueTS=newTS;
      return;
    }
    
    if (va_oldValue==value)
      return;

    if ((abs(value-va_oldValue)/va_oldValue)*100<linky_va_variation_threshold_report)
      return;

    va_oldValue=value;
    va_lastValueTS=newTS;

    LOGD("TINFO","TeleInfo threshold [PAPP] value:%.2f send to MQTT",value);
    sendMQTTUpdate("/energy_va/state",value);
  }
}

/* ======================================================================
Function:     setup
Description : Setup I/O and other one time startup stuff
Input   : -
Output  : - 
Comments: -
============================================================================ 
*/
void setup(){
  
  Watchdog.enable(10000);
  
  Serial.begin(115200);
  Serial2.begin(1200, SERIAL_8N1, RXD2, TXD2);

  memset(message, 0, 64); // padding with 0

  client.setBufferSize(1024);

  pinMode(pinRadioPwr, OUTPUT);
  digitalWrite(pinRadioPwr, HIGH); 

  radio.begin();                      // Initialisation du module NRF24
  radio.openReadingPipe(0, adresse);  // Ouverture du tunnel en LECTURE, avec le "nom" qu'on lui a donné
  radio.setPALevel(RF24_PA_HIGH);      
  radio.startListening();             // Démarrage de l'écoute du NRF24 

  // Init teleinfo
  tinfo.init();
  tinfo.attachData(DataCallback);

  configTime(gmtOffset_sec, daylightOffset_sec, ntpServer);

  Debug.begin(MQTT_DEVICENAME);

  WiFi.mode(WIFI_STA); //Optional
  WiFi.begin(WIFI_SSID, WIFI_KEY);

  LOGI("MAIN","Connecting to  WiFi SSID:%s",WIFI_SSID);
  
  while(WiFi.status() != WL_CONNECTED){
    Serial.print(".");
    delay(500);
  }
  LOGI("MAIN","Connected to the WiFi network %s",WIFI_SSID);
  LOGI("MAIN","Local IP %s",WiFi.localIP().toString().c_str());

  LOGD("TINFO","TeleInfo init:OK");

  client.setServer(MQTT_SERVER, MQTT_PORT);
  connectMQTT();
  
  sendMQTTEnergyKwHDiscoveryMsg();
  sendMQTTEnergyVADiscoveryMsg();
  sendMQTTEnergyGazM3DiscoveryMsg();
  sendMQTTBatteryDiscoveryMsg();
  sendMQTTPayloadErrorDiscoveryMsg();

  MQTT_DiscoveryMsg_Text_WIFI_SSID();
  MQTT_DiscoveryMsg_Text_WIFI_RSSI();
  MQTT_DiscoveryMsg_Text_IpAddr();
  MQTT_DiscoveryMsg_Text_MacAddr();
  MQTT_DiscoveryMsg_Text_PingAlive();

  server.begin();     // start the internal webserver

  ArduinoOTA.setHostname(MQTT_DEVICENAME);
  ArduinoOTA.setPassword(OTA_PASS);

  ArduinoOTA
    .onStart([]() {
      String type;
      if (ArduinoOTA.getCommand() == U_FLASH)
        type = "sketch";
      else // U_SPIFFS
        type = "filesystem";

      // NOTE: if updating SPIFFS this would be the place to unmount SPIFFS using SPIFFS.end()
      LOGW("MAIN","Start updating firmware" );
    })
    .onEnd([]() {
      LOGI("MAIN","\nEnd");
    })
    .onProgress([](unsigned int progress, unsigned int total) {
      LOGI("MAIN","Progress: %u%%\r", (progress / (total / 100)));
    })
    .onError([](ota_error_t error) {
      LOGE("MAIN","Error[%u]: ", error);
      if (error == OTA_AUTH_ERROR){ LOGE("MAIN","Auth Failed");}
      else if (error == OTA_BEGIN_ERROR) {LOGE("MAIN","Begin Failed");}
      else if (error == OTA_CONNECT_ERROR) {LOGE("MAIN","Connect Failed");}
      else if (error == OTA_RECEIVE_ERROR) {LOGE("MAIN","Receive Failed");}
      else if (error == OTA_END_ERROR){ LOGE("MAIN","End Failed");}
    });

  ArduinoOTA.begin();
  updateDataDiag();

  Watchdog.disable(); 
}

void addCircularLog(char * event){
  char * tmp=(char*)malloc(64*sizeof(char));
  sprintf(tmp,"%s",event);
  cLog.unshift(tmp);
  if (cLog.size()>90) {
    free((char*) cLog.pop());                   // Removing last items from the stack and free memory of allocated data
  }
}
boolean sendMqttMsg(const char* topic,DynamicJsonDocument doc){
    String jsonBuffer;
    size_t n = serializeJson(doc, jsonBuffer);
    bool published=client.publish(topic, jsonBuffer.c_str(), n);
    return published;
}

void sendMQTTUpdate(const char rootTopic[],double value){
  connectMQTT();

  if (client.connected()){
    char stateTopic[256];
    char mqttPayload[256];

    sprintf(stateTopic,"homeassistant/sensor/%s%s",MQTT_DEVICENAME,rootTopic);
    sprintf(mqttPayload,"{\"value\":%f}",value);
   
    int n =strlen(mqttPayload);
    client.publish(stateTopic, mqttPayload, n);

    LOGD("MQTT","MQTT message topic:%s value:%f payload:%s",stateTopic,value,mqttPayload);
  }
}

void sendMQTTUpdateStr(const char rootTopic[],char * value){

  connectMQTT();

  if (client.connected()){
    char stateTopic[256];
    char mqttPayload[256];
    
    sprintf(stateTopic,"homeassistant/sensor/%s%s",MQTT_DEVICENAME,rootTopic);
    sprintf(mqttPayload,"{\"value\":\"%s\",\"gazvol_oldvalue\":\"%.2f\"}",value,gazvol_oldValue); // to be removed not really generic, but kept to understand
   
    int n =strlen(mqttPayload);
    client.publish(stateTopic, mqttPayload, n);

    LOGD("MQTT","MQTT message topic:%s value:%s payload:%s",stateTopic,value,mqttPayload);
  }
  return;
}

DynamicJsonDocument getDeviceBlock(){
    
    DynamicJsonDocument doc(1024);
    
    doc["dev"]["ids"][0]=MQTT_DEVICENAME;
    doc["dev"]["name"]="Linky Gazpar Receiver";
    doc["dev"]["mdl"]=MQTT_DEVICENAME;
    doc["dev"]["mf"]="VIBR";
    doc["dev"]["sw"]=fwVersion;
    doc["dev"]["hw_version"]="1.1";

    /*
    doc["availability"]["topic"]=AVAILABILITY_TOPIC;
    doc["availability"]["payload_available"]="ONLINE";
    doc["availability"]["payload_not_available"]="OFFLINE";
    */

    return doc;
}
void MQTT_DiscoveryMsg_Text_WIFI_SSID(){
  
  DynamicJsonDocument doc(2048);

  doc["name"] = "WiFi SSID";
  char ID[64];
  sprintf(ID,"%s_WIFI_SSID",MQTT_DEVICENAME);
  doc["uniq_id"]=ID;

  doc["icon"]="mdi:wifi";
  
  doc["qos"]=0;
  doc["retain"]=true;
  doc["entity_category"]="diagnostic";
  doc["state_topic"]=WIFI_SSID_STATE_TOPIC;
  doc["value_template"]="{{ value_json.value }}";
  
  DynamicJsonDocument dev=getDeviceBlock();
  doc["dev"]=dev["dev"];
  doc["availability"]=dev["availability"];

  bool published= sendMqttMsg(DISCOVERY_WIFI_SSID_TOPIC,doc);

}

void MQTT_DiscoveryMsg_Text_WIFI_RSSI(){
  
  DynamicJsonDocument doc(2048);

  doc["name"] = "WiFi RSSI";
  char ID[64];
  sprintf(ID,"%s_WIFI_RSSI",MQTT_DEVICENAME);
  doc["uniq_id"]=ID;

  doc["icon"]="mdi:wifi-strength-1";
  
  doc["qos"]=0;
  doc["retain"]=true;
  doc["entity_category"]="diagnostic";
  doc["unit_of_measurement"]="dBm";
  doc["state_topic"]=WIFI_RSSI_STATE_TOPIC;
  doc["value_template"]="{{ value_json.value }}";
  
  DynamicJsonDocument dev=getDeviceBlock();
  doc["dev"]=dev["dev"];
  doc["availability"]=dev["availability"];

  bool published= sendMqttMsg(DISCOVERY_WIFI_RSSI_TOPIC,doc);

}

void MQTT_DiscoveryMsg_Text_IpAddr(){
  
  DynamicJsonDocument doc(2048);

  doc["name"] = "IP Addr";
  char ID[64];
  sprintf(ID,"%s_IP_ADDR",MQTT_DEVICENAME);
  doc["uniq_id"]=ID;

  doc["icon"]="mdi:ip-network";
  
  doc["qos"]=0;
  doc["retain"]=true;
  doc["entity_category"]="diagnostic";
  doc["state_topic"]=IP_ADDR_STATE_TOPIC;
  doc["value_template"]="{{ value_json.value }}";
  
  DynamicJsonDocument dev=getDeviceBlock();
  doc["dev"]=dev["dev"];
  doc["availability"]=dev["availability"];

  bool published= sendMqttMsg(DISCOVERY_IP_ADDR_TOPIC,doc);

}

void MQTT_DiscoveryMsg_Text_MacAddr(){
  
  DynamicJsonDocument doc(2048);

  doc["name"] = "Mac Addr";
  char ID[64];
  sprintf(ID,"%s_MAC_ADDR",MQTT_DEVICENAME);
  doc["uniq_id"]=ID;

  doc["icon"]="mdi:web";
  
  doc["qos"]=0;
  doc["retain"]=true;
  doc["entity_category"]="diagnostic";
  doc["state_topic"]=MAC_ADDR_STATE_TOPIC;
  doc["value_template"]="{{ value_json.value }}";
  
  DynamicJsonDocument dev=getDeviceBlock();
  doc["dev"]=dev["dev"];
  doc["availability"]=dev["availability"];

  bool published= sendMqttMsg(DISCOVERY_MAC_ADDR_TOPIC,doc);

}

void MQTT_DiscoveryMsg_Text_PingAlive(){
  
  DynamicJsonDocument doc(2048);

  doc["name"] = "Ping Alive";
  char ID[64];
  sprintf(ID,"%s_PING_ALIVE",MQTT_DEVICENAME);
  doc["uniq_id"]=ID;

  doc["icon"]="mdi:heart-pulse";
  doc["unit_of_measurement"]="min";

  doc["qos"]=0;
  doc["retain"]=true;
  doc["entity_category"]="diagnostic";
  doc["state_topic"]=PING_ALIVE_STATE_TOPIC;
  doc["value_template"]="{{ value_json.value }}";
  
  DynamicJsonDocument dev=getDeviceBlock();
  doc["dev"]=dev["dev"];
  doc["availability"]=dev["availability"];

  bool published= sendMqttMsg(DISCOVERY_PING_ALIVE_TOPIC,doc);

}

void sendMQTTEnergyVADiscoveryMsg() {
  
  char discoveryTopic[256];
  char stateTopic[256];
  char buffer[1024];
  char tmp[128];
  sprintf(discoveryTopic,"homeassistant/sensor/%s/energy_va/config",MQTT_DEVICENAME);
  sprintf(stateTopic,"homeassistant/sensor/%s/energy_va/state",MQTT_DEVICENAME);

  DynamicJsonDocument doc(2048);
  
  sprintf(tmp,"%s energy",MQTT_DEVICENAME);
  doc["name"] = tmp;
  doc["stat_t"]   = stateTopic;
  doc["stat_cla"]   = "measurement";
  doc["unit_of_meas"] = "W";
  doc["dev_cla"] = "energy";
  doc["frc_upd"] = true;
  doc["val_tpl"] = "{{ value_json.value }}";
  
  sprintf(tmp,"%s_VA",MQTT_DEVICENAME);
  doc["uniq_id"]=tmp;
  
  DynamicJsonDocument dev=getDeviceBlock();
  doc["dev"]=dev["dev"];
  //doc["availability"]=dev["availability"];
   
  size_t n = serializeJson(doc, buffer);
  client.publish(discoveryTopic, buffer, n);
}

void sendMQTTEnergyKwHDiscoveryMsg() {

  char discoveryTopic[256];
  char stateTopic[256];
  char buffer[1024];
  char tmp[128];

  sprintf(discoveryTopic,"homeassistant/sensor/%s/energy_kwh/config",MQTT_DEVICENAME);
  sprintf(stateTopic,"homeassistant/sensor/%s/energy_kwh/state",MQTT_DEVICENAME);

  DynamicJsonDocument doc(2048);

  sprintf(tmp,"%s energy",MQTT_DEVICENAME);
  doc["name"] = tmp;
  doc["stat_t"]   = stateTopic;
  doc["stat_cla"]   = "total_increasing";
  doc["unit_of_meas"] = "kWh";
  doc["dev_cla"] = "energy";
  doc["frc_upd"] = true;
  doc["val_tpl"] = "{{ value_json.value }}";

  sprintf(tmp,"%s_KWH",MQTT_DEVICENAME);
  doc["uniq_id"]=tmp;
  
  DynamicJsonDocument dev=getDeviceBlock();
  doc["dev"]=dev["dev"];
  //doc["availability"]=dev["availability"];
   
  bool published= sendMqttMsg(discoveryTopic,doc);
}

void sendMQTTEnergyGazM3DiscoveryMsg() {
  
  char discoveryTopic[256];
  char stateTopic[256];
  char buffer[1024];
  char tmp[128];
  
  sprintf(discoveryTopic,"homeassistant/sensor/%s/energy_m3/config",MQTT_DEVICENAME);
  sprintf(stateTopic,"homeassistant/sensor/%s/energy_m3/state",MQTT_DEVICENAME);

  DynamicJsonDocument doc(2048);

  sprintf(tmp,"%s gaz",MQTT_DEVICENAME);
  doc["name"] = tmp;

  doc["stat_t"]   = stateTopic;
  doc["stat_cla"]   = "total_increasing";
  doc["unit_of_meas"] = "m³";
  doc["dev_cla"] = "gas";
  doc["frc_upd"] = true;
  doc["val_tpl"] = "{{ value_json.value }}";
  
  sprintf(tmp,"%s_M3",MQTT_DEVICENAME);
  doc["uniq_id"]=tmp;
  
  DynamicJsonDocument dev=getDeviceBlock();
  doc["dev"]=dev["dev"];
  //doc["availability"]=dev["availability"];
   
 bool published= sendMqttMsg(discoveryTopic,doc);
}

void sendMQTTBatteryDiscoveryMsg() {

  char discoveryTopic[256];
  char stateTopic[256];
  char buffer[1024];
  char tmp[128];
  
  sprintf(discoveryTopic,"homeassistant/sensor/%s/bat/config",MQTT_DEVICENAME);
  sprintf(stateTopic,"homeassistant/sensor/%s/bat/state",MQTT_DEVICENAME);

  DynamicJsonDocument doc(2048);

  sprintf(tmp,"%s battery",MQTT_DEVICENAME);
  doc["name"] = tmp;

  doc["stat_t"]   = stateTopic;
  doc["unit_of_meas"] = "%";
  doc["dev_cla"] = "battery";
  doc["frc_upd"] = true;
  doc["val_tpl"] = "{{ value_json.value }}";

  sprintf(tmp,"%s_BAT",MQTT_DEVICENAME);
  doc["uniq_id"]=tmp;
  
  DynamicJsonDocument dev=getDeviceBlock();
  doc["dev"]=dev["dev"];
  //doc["availability"]=dev["availability"];
   
bool published= sendMqttMsg(discoveryTopic,doc);
}

void sendMQTTPayloadErrorDiscoveryMsg() {

  char discoveryTopic[256];
  char stateTopic[256];
  char buffer[1024];
  char tmp[128];
  
  sprintf(discoveryTopic,"homeassistant/sensor/%s/payload_error/config",MQTT_DEVICENAME);
  sprintf(stateTopic,"homeassistant/sensor/%s/payload_error/state",MQTT_DEVICENAME);

  DynamicJsonDocument doc(2048);

  sprintf(tmp,"%s payload error",MQTT_DEVICENAME);
  doc["name"] = tmp;

  doc["stat_t"]   = stateTopic;
  doc["frc_upd"] = true;
  doc["val_tpl"] = "{{ value_json.value }}";

  sprintf(tmp,"%s_ERR",MQTT_DEVICENAME);
  doc["uniq_id"]=tmp;
  
  DynamicJsonDocument dev=getDeviceBlock();
  doc["dev"]=dev["dev"];
  //doc["availability"]=dev["availability"];
   
bool published= sendMqttMsg(discoveryTopic,doc);
}

String MacAddr;

void connectWIFI(){
  
  while (WiFi.status() != WL_CONNECTED) {                     // attempt to connect to Wifi network
    status = WiFi.begin(WIFI_SSID, WIFI_KEY); 
    WiFi.setSleep(false);                
    uint8_t timeout = 10;
    while (timeout && (WiFi.status() != WL_CONNECTED)) { // wait 10 seconds for connection: 
      timeout--;
      delay(1000);
    }
    if (WiFi.status()==WL_CONNECTED){
      LOGI("MAIN","WiFi connected to ssid:%s",WIFI_SSID);
    }
  } 
  return;
}

void connectMQTT(){

  if (WiFi.status() != WL_CONNECTED ){
    LOGI("MAIN","WiFi not connected to ssid:%s",WIFI_SSID);
    connectWIFI();
  }else{
    LOGI("MAIN","WiFi connected to ssid:%s",WIFI_SSID);
  }

  client.setBufferSize(4096);

  if (WiFi.status() == WL_CONNECTED ){ 
    client.setKeepAlive(5);
    uint8_t timeout = 10;
    while (timeout && !client.connect(MQTT_DEVICENAME, MQTT_USER, MQTT_PASS)){
      timeout--;
      delay(1000);
    }

    if (client.connect(MQTT_DEVICENAME, MQTT_USER, MQTT_PASS)) {
      LOGI("MAIN","Connected to MQTT");
    }else {
      LOGE("MAIN","NOT Connected to MQTT");

    }
  }
}
bool publishToTopicFloat(float value,const char *topic,const char * key,bool retain){
 
  char mqttPayload[256];
  sprintf(mqttPayload,"{\"%s\":%f}",key,value);
  size_t n=strlen(mqttPayload);

  bool published=client.publish(topic,(const unsigned char*)mqttPayload,n,true);
 
  return published;
}

bool publishToTopicStr(char * value,const char *topic,const char * key,bool retain){
  
  char mqttPayload[256];

  sprintf(mqttPayload,"{\"%s\":\"%s\"}",key,value);
  size_t n=strlen(mqttPayload);

  bool published=client.publish(topic,(const unsigned char*) mqttPayload, n,retain);
 
  return published;
}

void updateDataDiag(){

  int rssi = WiFi.RSSI();
  char * sRssi=(char*)malloc(16*(sizeof(char)));
  sprintf(sRssi,"%d",rssi);
  publishToTopicStr((char*)sRssi,WIFI_RSSI_STATE_TOPIC,"value",false); 
  free(sRssi);

  publishToTopicStr((char*)WIFI_SSID,WIFI_SSID_STATE_TOPIC,"value",false); 
  
  char* IpAddr=(char*)malloc(24*(sizeof(char)));
  IPAddress ip=WiFi.localIP();
  sprintf(IpAddr,"%d.%d.%d.%d",ip[0],ip[1],ip[2],ip[3]);
  publishToTopicStr((char*)IpAddr,IP_ADDR_STATE_TOPIC,"value",false); 
  free(IpAddr);

  MacAddr=WiFi.macAddress();
  publishToTopicStr((char*)MacAddr.c_str(),MAC_ADDR_STATE_TOPIC,"value",false); 
  
  pingAliveCount++;
  publishToTopicFloat(pingAliveCount,PING_ALIVE_STATE_TOPIC,"value",false);
  
}

char * getValue_c(char *data, const char *sep, const char *key){


    char * d = strtok(data, sep);
    while (d != NULL) {

        if (d[0]==key[0]){

          return d+2;
        }
        d = strtok(NULL, sep);
    }

    return NULL;
}

/* ======================================================================
Function: loop
Purpose : infinite loop main code
Input   : -
Output  : - 
Comments: -
====================================================================== */
void loop(){

   //Watchdog.enable(10000);
   ArduinoOTA.handle();
   client.loop();

  if ( Serial2.available() ) {           // Teleinformation processing
    tinfo.process(Serial2.read());
  }

  if (radio.available()) {

    radio.read(&message, sizeof(message));                        // Si un message vient d'arriver, on le charge dans la variable "message"
   
    #ifdef GG_DEBUG
      GG_DEBUG_PRINT("Message recu Hex: "); 
      debughex(message,strlen(message));
    #endif

   if (strlen(message)>0){
    char tmp[64];
    char *ret;
    #if CRPYPTO==1
      const char* decodedPtr = decode_128bits(message,strlen(message));

      GG_DEBUG_PRINT("Message uncrypted:"); 
      GG_DEBUG_PRINTLN(decodedPtr);
      
      sprintf(tmp,"%s",decodedPtr);
      addCircularLog((char*)decodedPtr);
    #else
      struct tm timeinfo;
      char dt[32];
      if(!getLocalTime(&timeinfo)){
        LOGE("MAIN","Failed to obtain time");
        return;
      }
     
      sprintf(dt," %02d/%02d/%02d %02d:%02d:%02d",1900+timeinfo.tm_year,timeinfo.tm_mon+1,timeinfo.tm_mday,timeinfo.tm_hour,timeinfo.tm_min,timeinfo.tm_sec);
      sprintf(tmp,"%s->%s",dt,message);
      addCircularLog((char*)tmp);
    #endif 

      ret=getValue_c(tmp,";","v");
      if (ret!=NULL){
        float bat_percent=(atoi(ret)-3200)/10;    //  4,2V --> 100% et 3,2 --> 0%                                            
        sendMQTTUpdate("/bat/state",bat_percent);
      }
      #if CRPYPTO==1
        sprintf(tmp,"%s",decodedPtr);
      #else
         sprintf(tmp,"%s",message);
      #endif

      ret=getValue_c(tmp,";","p");
      if (ret!=NULL){
        double gaz_vol=atof(ret)/100;                                             
        
        if (gaz_vol>1)                                   
          sendMQTTUpdate("/energy_m3/state",gaz_vol);
        else{

      #if CRPYPTO==1
        sprintf(tmp,"%s",decodedPtr);
      #else
         sprintf(tmp,"%s",message);
      #endif
          sendMQTTUpdateStr("/payload_error/state",tmp);
        }
        gazvol_oldValue=gaz_vol;
      }
    }
  }

  WiFiClient wclient = server.available();

  if (wclient) {
    String currentLine = "";
    while (wclient.connected()) { 
      
     if (wclient.available()) {            // if there's bytes to read from the client,
      char c = wclient.read();             // read a byte, then
  	  if (c == '\n') {                    // if the byte is a newline character
                                          // if the current line is blank, you got two newline characters in a row.
                                          // that's the end of the client HTTP request, so send a response:

        if (currentLine.length() == 0) {

            wclient.println("HTTP/1.1 200 OK");
            wclient.println("Content-type:text/html");
            wclient.println();

            wclient.println("<pre>output gazpar log:");

            for(int i=0;i<cLog.size();i++){
              wclient.println((char*)cLog[i]);
            }
                                                                            
            wclient.println();
            break;
          }else {      // if you got a newline, then clear currentLine:
            currentLine = "";
          }
        }else if (c != '\r') {    // if you got anything else but a carriage return character,
          currentLine += c;      // add it to the end of the currentLine
        }

        // Check to see if the client request was "GET /H" or "GET /L":

        if (currentLine.endsWith("GET /H")) {
        }
      }
    }
    // close the connection:

    wclient.stop();
  }
  unsigned long now = millis();
  if (now - lastUpdateDiag > UpdateDiagInterval_ms) {
    updateDataDiag();
    lastUpdateDiag = now;
  }
  Debug.handle();
  //Watchdog.disable();
}
