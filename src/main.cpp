/*
__   _____ ___ ___        Author: Vincent BESSON
 \ \ / /_ _| _ ) _ \      Release: 0.31
  \ V / | || _ \   /      Date: 20221227
   \_/ |___|___/_|_\      Description: Interface Linky MQTT with NRF24 Gazpar vers HA
                2022      Licence: Creative Commons
______________________

Release changelog:
  +20221228: False positive, remove gazvol 0 value, add payload log for investigation
  +20221227: Instability, changing String to char
*/ 


#include <SPI.h>
#include <Time.h>

#include <WiFi101.h>
#include <Wire.h>
#include "Adafruit_HTU31D.h"
#include <PubSubClient.h>
#include <Adafruit_SleepyDog.h>

#include <ArduinoJson.h>
#include <LibTeleinfo.h>

#include <RF24.h>
#include "pwd.h"

#include <CircularBuffer.h>

//#include <Base64.h> // https://github.com/agdl/Base64
#include <AES.h>    // https://forum.arduino.cc/index.php?topic=88890.0
AES aes ;

const uint16_t maxMessageSize = 32;    // message size + 1 NEEDS to be a multiple of N_BLOCK (16)

uint8_t key128bits[] = AES_KEY; // KEEP SECRET !
const uint8_t iv128bits[]  = AES_IV; // NO NEED TO KEEP SECRET

TInfo          tinfo; // Teleinfo object

char ssid[] = WIFI_SSID;        // your network SSID (name)
char pass[] = WIFI_KEY;

const char* mqttServer = MQTT_SERVER; // The IP of your MQTT broker
const int   mqttPort = MQTT_PORT;
const char* mqttUser = MQTT_USER;
const char* mqttPassword = MQTT_PASS;

const char * fwVersion="0.31b";

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

#define WINC_CS   8
#define WINC_IRQ  7
#define WINC_RST  4
#define WINC_EN   2     // or, tie EN to VCC

#define pinRadioPwr   12 
#define pinCE   11                // On associe la broche "CE" du NRF24L01 à la sortie digitale D7 de l'arduino
#define pinCSN  10                // On associe la broche "CSN" du NRF24L01 à la sortie digitale D8 de l'arduino
#define tunnel  "D6E1A"           // On définit le "nom de tunnel" (5 caractères) à travers lequel on va recevoir les données de l'émetteur

const byte adresse[6] = tunnel;       // Mise au format "byte array" du nom du tunnel
char message[64];                     // Avec cette librairie, on est "limité" à 32 caractères par message

RF24 radio(pinCE, pinCSN);    // Instanciation du NRF24L01

#define GG_DEBUG

#ifdef GG_DEBUG
  #define GG_DEBUG_PRINTLN(x) Serial.println(x)
  #define GG_DEBUG_PRINT(x) Serial.print(x)
   #define GG_DEBUG_PRINTHEX(x) Serial.print(x,HEX)
#else
  #define GG_DEBUG_PRINTLN(x)
  #define GG_DEBUG_PRINT(x)
  #define GG_DEBUG_PRINTHEX(x)
#endif 

#define RADIO_ON  1
#define TELEINFO_ON  1


CircularBuffer<void*, 100> cLog;

WiFiServer server(80);

/*************** FUNCTION DECLARATION ************************************/

void MQTT_connect();

char * getValue_c(char * data, char *sep, char *key);
const char* encode_128bits(const char* texteEnClair);
const char* decode_128bits(const char* texteEnBase64,int len);
void printUptime(void);

void debughex(const char * message,int len);
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

/************ Global State (you don't need to change this!) ******************/

const char deviceName[] = "WINC 1500 Linky1"; 
const char deviceID[] = "WINC1500_LINKY_1"; 
void software_Reboot(){
  /*int countdownMS =*/ Watchdog.enable(10);
}

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

const char* decode_128bits(const char* texteEnBase64,int len){
  // static allocation of buffers to ensure the stick around when returning from the function until the next call
  static uint8_t message[maxMessageSize];
  static uint8_t cryptedMessage[maxMessageSize];

  uint8_t iv[N_BLOCK]; // memory is modified during the call
  memcpy(iv, iv128bits, N_BLOCK);

  memset(message, 0, maxMessageSize); // padding with 0
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

/* ======================================================================
Function: printUptime 
Purpose : print pseudo uptime value
Input   : -
Output  : - 
Comments: compteur de secondes basique sans controle de dépassement
          En plus SoftwareSerial rend le compteur de millis() totalement
          A la rue, donc la precision de ce compteur de seconde n'est
          pas fiable du tout, dont acte !!!
====================================================================== */
void printUptime(void){
  GG_DEBUG_PRINT(millis()/1000);
  GG_DEBUG_PRINT(F("s\t"));
}

/* ======================================================================
Function: DataCallback 
Purpose : callback when we detected new or modified data received
Input   : linked list pointer on the concerned data
          current flags value
Output  : - 
Comments: -
====================================================================== */
void DataCallback(ValueList * me, uint8_t  flags){
  // Show our not accurate second counter
  printUptime();
  float value=0;

  if (flags & TINFO_FLAGS_ADDED) 
    GG_DEBUG_PRINT(F("NEW -> "));

  if (flags & TINFO_FLAGS_UPDATED)
    GG_DEBUG_PRINT(F("MAJ -> "));

  // Display values
  GG_DEBUG_PRINT(me->name);
  GG_DEBUG_PRINT("=");
  GG_DEBUG_PRINTLN(me->value);

  newTS= millis();
  
  if (!strcmp(me->name,"BASE")){
    value=roundf((atof(me->value))*100.0)/100.0;
    GG_DEBUG_PRINT("new BASE value");
    if ((newTS-kWh_lastValueTS)/1000>linky_report_interval){
      GG_DEBUG_PRINTLN("reporting based on lastTS");
      //sendMQTTEnergyKwHUpdateMsg(value);
      float val_f=value/1000; // We are reporting kWh not Wh
      sendMQTTUpdate("/energy_kwh/state",val_f);
      kWh_lastValueTS=newTS;
      kWh_oldValue=value;
      return;
    }
  }

  if (!strcmp(me->name,"PAPP")){
    GG_DEBUG_PRINT("new PAPP value");
    value=roundf((atof(me->value))*100.0)/100.0;

    if ((newTS-va_lastValueTS)/1000>linky_report_interval){
      GG_DEBUG_PRINTLN("reporting based on lastTS");
      //float val_f=value;           // We are reporting kWh not Wh
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
    GG_DEBUG_PRINTLN("reporting based on threshold");
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
  
  GG_DEBUG_PRINT(F("========================================"));
  GG_DEBUG_PRINT(F(__FILE__));
  GG_DEBUG_PRINT(F(__DATE__ " " __TIME__));
  GG_DEBUG_PRINTLN();

  Serial.begin(115200);
  Serial1.begin(1200);

  WiFi.setPins(WINC_CS, WINC_IRQ, WINC_RST, WINC_EN);
  client.setBufferSize(1024);

  if (WiFi.status() == WL_NO_SHIELD){
    GG_DEBUG_PRINTLN("WINC1500 not present");
    while (true);
  }
  pinMode(pinRadioPwr, OUTPUT);
  digitalWrite(pinRadioPwr, HIGH); 

  radio.begin();                      // Initialisation du module NRF24
  radio.openReadingPipe(0, adresse);  // Ouverture du tunnel en LECTURE, avec le "nom" qu'on lui a donné
  radio.setPALevel(RF24_PA_HIGH);      
  radio.startListening();             // Démarrage de l'écoute du NRF24 

  // Init teleinfo
  tinfo.init();

  tinfo.attachData(DataCallback);

  printUptime();
  GG_DEBUG_PRINT(F("Teleinfo started"));

  client.setServer(mqttServer, mqttPort);
  MQTT_connect();
  
  sendMQTTEnergyKwHDiscoveryMsg();
  sendMQTTEnergyVADiscoveryMsg();
  sendMQTTEnergyGazM3DiscoveryMsg();
  sendMQTTBatteryDiscoveryMsg();
  sendMQTTPayloadErrorDiscoveryMsg();

  server.begin();     // start the internal webserver

  Watchdog.disable(); 
}

void addCircularLog(char * event){
  char * tmp=(char*)malloc(32*sizeof(char));
  sprintf(tmp,"%s",event);
  cLog.unshift(tmp);
  if (cLog.size()>90) {
    free((char*) cLog.pop());                   // Removing last items from the stack and free memory of allocated data
  }
}

void sendMQTTUpdate(const char rootTopic[],double value){
  MQTT_connect();

  if (client.connected()){
    char stateTopic[256];
    sprintf(stateTopic,"homeassistant/sensor/%s%s",deviceID,rootTopic);
    DynamicJsonDocument doc(512);
    
    char buffer[512];
    size_t n = serializeJson(doc, buffer);
    
    doc["value"]=value;
  
    n = serializeJson(doc, buffer);
    client.publish(stateTopic, buffer, n);

    GG_DEBUG_PRINT(stateTopic);
    GG_DEBUG_PRINT(":");
    GG_DEBUG_PRINTLN(value);
  }
}

void sendMQTTUpdateStr(const char rootTopic[],char * value){
  MQTT_connect();

  if (client.connected()){
    char stateTopic[256];
    sprintf(stateTopic,"homeassistant/sensor/%s%s",deviceID,rootTopic);
    DynamicJsonDocument doc(512);
    
    char buffer[512];
    size_t n = serializeJson(doc, buffer);
    
    doc["value"]=value;
    doc["gazvol_oldvalue"]=gazvol_oldValue;             // to be removed not really generic, but kept to understand

    n = serializeJson(doc, buffer);
    client.publish(stateTopic, buffer, n);

    GG_DEBUG_PRINT(stateTopic);
    GG_DEBUG_PRINT(":");
    GG_DEBUG_PRINTLN(value);
  }
}

void sendMQTTEnergyVADiscoveryMsg() {
  
  char discoveryTopic[256];
  char stateTopic[256];
  char buffer[1024];
  char tmp[128];
  sprintf(discoveryTopic,"homeassistant/sensor/%s/energy_va/config",deviceID);
  sprintf(stateTopic,"homeassistant/sensor/%s/energy_va/state",deviceID);

  DynamicJsonDocument doc(2048);
  
  sprintf(tmp,"%s energy",deviceName);
  doc["name"] = tmp;
  doc["stat_t"]   = stateTopic;
  doc["stat_cla"]   = "measurement";
  doc["unit_of_meas"] = "W";
  doc["dev_cla"] = "energy";
  doc["frc_upd"] = true;
  doc["val_tpl"] = "{{ value_json.value }}";
  
  sprintf(tmp,"%s_VA",deviceID);
  doc["uniq_id"]=tmp;
  
  sprintf(tmp,"VIBR_%s",deviceID);
  doc["dev"]["ids"][0]=tmp;

  doc["dev"]["name"]=deviceID;
  doc["dev"]["mdl"]="WINC1500";
  doc["dev"]["mf"]="Adafruit custom";
  doc["dev"]["sw"]=fwVersion; 
   
  size_t n = serializeJson(doc, buffer);
  client.publish(discoveryTopic, buffer, n);
}

void sendMQTTEnergyKwHDiscoveryMsg() {

  char discoveryTopic[256];
  char stateTopic[256];
  char buffer[1024];
  char tmp[128];

  sprintf(discoveryTopic,"homeassistant/sensor/%s/energy_kwh/config",deviceID);
  sprintf(stateTopic,"homeassistant/sensor/%s/energy_kwh/state",deviceID);

  DynamicJsonDocument doc(2048);

  sprintf(tmp,"%s energy",deviceName);
  doc["name"] = tmp;
  doc["stat_t"]   = stateTopic;
  doc["stat_cla"]   = "total_increasing";
  doc["unit_of_meas"] = "kWh";
  doc["dev_cla"] = "energy";
  doc["frc_upd"] = true;
  doc["val_tpl"] = "{{ value_json.value }}";

  sprintf(tmp,"%s_KWH",deviceID);
  doc["uniq_id"]=tmp;
  
  sprintf(tmp,"VIBR_%s",deviceID);
  doc["dev"]["ids"][0]=tmp;
  
  doc["dev"]["name"]=deviceID;
  doc["dev"]["mdl"]="WINC1500";
  doc["dev"]["mf"]="Adafruit custom";
  doc["dev"]["sw"]=fwVersion; 
   
  size_t n = serializeJson(doc, buffer);
  client.publish(discoveryTopic, buffer, n);
}

void sendMQTTEnergyGazM3DiscoveryMsg() {
  
  char discoveryTopic[256];
  char stateTopic[256];
  char buffer[1024];
  char tmp[128];
  
  sprintf(discoveryTopic,"homeassistant/sensor/%s/energy_m3/config",deviceID);
  sprintf(stateTopic,"homeassistant/sensor/%s/energy_m3/state",deviceID);

  DynamicJsonDocument doc(2048);

  sprintf(tmp,"%s gaz",deviceName);
  doc["name"] = tmp;

  doc["stat_t"]   = stateTopic;
  doc["stat_cla"]   = "total_increasing";
  doc["unit_of_meas"] = "m³";
  doc["dev_cla"] = "gas";
  doc["frc_upd"] = true;
  doc["val_tpl"] = "{{ value_json.value }}";
  
  sprintf(tmp,"%s_M3",deviceID);
  doc["uniq_id"]=tmp;
  
  sprintf(tmp,"VIBR_%s",deviceID);
  doc["dev"]["ids"][0]=tmp;
  doc["dev"]["name"]=deviceID;
  doc["dev"]["mdl"]="WINC1500";
  doc["dev"]["mf"]="Adafruit custom";
  doc["dev"]["sw"]=fwVersion; 
   
  size_t n = serializeJson(doc, buffer);
  client.publish(discoveryTopic, buffer, n);
}

void sendMQTTBatteryDiscoveryMsg() {

  char discoveryTopic[256];
  char stateTopic[256];
  char buffer[1024];
  char tmp[128];
  
  sprintf(discoveryTopic,"homeassistant/sensor/%s/bat/config",deviceID);
  sprintf(stateTopic,"homeassistant/sensor/%s/bat/state",deviceID);

  DynamicJsonDocument doc(2048);

  sprintf(tmp,"%s battery",deviceName);
  doc["name"] = tmp;

  doc["stat_t"]   = stateTopic;
  doc["unit_of_meas"] = "%";
  doc["dev_cla"] = "battery";
  doc["frc_upd"] = true;
  doc["val_tpl"] = "{{ value_json.value }}";

  sprintf(tmp,"%s_BAT",deviceID);
  doc["uniq_id"]=tmp;
  
  sprintf(tmp,"VIBR_%s",deviceID);
  doc["dev"]["ids"][0]=tmp;

  doc["dev"]["name"]=deviceID;
  doc["dev"]["mdl"]="WINC1500";
  doc["dev"]["mf"]="Adafruit custom";
  doc["dev"]["sw"]=fwVersion; 
   
  size_t n = serializeJson(doc, buffer);
  client.publish(discoveryTopic, buffer, n);
}

void sendMQTTPayloadErrorDiscoveryMsg() {

  char discoveryTopic[256];
  char stateTopic[256];
  char buffer[1024];
  char tmp[128];
  
  sprintf(discoveryTopic,"homeassistant/sensor/%s/payload_error/config",deviceID);
  sprintf(stateTopic,"homeassistant/sensor/%s/payload_error/state",deviceID);

  DynamicJsonDocument doc(2048);

  sprintf(tmp,"%s payload error",deviceName);
  doc["name"] = tmp;

  doc["stat_t"]   = stateTopic;
  doc["frc_upd"] = true;
  doc["val_tpl"] = "{{ value_json.value }}";

  sprintf(tmp,"%s_ERR",deviceID);
  doc["uniq_id"]=tmp;
  
  sprintf(tmp,"VIBR_%s",deviceID);
  doc["dev"]["ids"][0]=tmp;

  doc["dev"]["name"]=deviceID;
  doc["dev"]["mdl"]="WINC1500";
  doc["dev"]["mf"]="Adafruit custom";
  doc["dev"]["sw"]=fwVersion; 
   
  size_t n = serializeJson(doc, buffer);
  client.publish(discoveryTopic, buffer, n);
}

void printWiFiData() {

  // print your WiFi shield's IP address:
  IPAddress ip = WiFi.localIP();
  GG_DEBUG_PRINT("IP Address: ");
  GG_DEBUG_PRINTLN(ip);

  // print your subnet mask:
  IPAddress subnet = WiFi.subnetMask();
  GG_DEBUG_PRINT("NetMask: ");
  GG_DEBUG_PRINTLN(subnet);
  // print your gateway address:
  IPAddress gateway = WiFi.gatewayIP();
  GG_DEBUG_PRINT("Gateway: ");
  GG_DEBUG_PRINTLN(gateway);
}
void MQTT_connect() {
  
  while (WiFi.status() != WL_CONNECTED) {                     // attempt to connect to Wifi network
   GG_DEBUG_PRINT("WIFI: Attempting to connect to SSID: ");
   GG_DEBUG_PRINTLN(ssid);

   status = WiFi.begin(ssid, pass);                 
   uint8_t timeout = 10;
   while (timeout && (WiFi.status() != WL_CONNECTED)) {       // wait 10 seconds for connection:
    timeout--;
    delay(1000);
   }
   printWiFiData();
  }
  
  GG_DEBUG_PRINTLN("MQTT: Connecting");                         // Stop if already connected.

  if (!client.loop()) {
    GG_DEBUG_PRINTLN("MQTT: Client has disconnected...");
    client.disconnect();
    if (client.connect(deviceName, mqttUser, mqttPassword)) {
      GG_DEBUG_PRINTLN("MQTT: Connected");
    } else {
      GG_DEBUG_PRINT("MQTT: connection failed with state :");
      GG_DEBUG_PRINTLN(client.state());
    }
  }
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
    
  if ( Serial1.available() ) {                                    // Teleinformation processing
    tinfo.process(Serial1.read());
  }

  if (radio.available()) {
    radio.read(&message, sizeof(message));                        // Si un message vient d'arriver, on le charge dans la variable "message"
    
    #ifdef GG_DEBUG
      GG_DEBUG_PRINT("Message reçu cyphered: "); 
      debughex(message,strlen(message));
    #endif
  
    const char* decodedPtr = decode_128bits(message,strlen(message));

    GG_DEBUG_PRINT("Message uncrypted:"); 
    GG_DEBUG_PRINTLN(decodedPtr);
    
    char tmp[32];
    char *ret;
    sprintf(tmp,"%s",decodedPtr);

    addCircularLog((char*)decodedPtr);

    ret=getValue_c(tmp,";","v");
    if (ret!=NULL){
      float bat_percent=(atoi(ret)-3200)/10;    //  4,2V --> 100% et 3,2 --> 0%                                            
      GG_DEBUG_PRINT("batterie %:");
      GG_DEBUG_PRINTLN(bat_percent);
      sendMQTTUpdate("/bat/state",bat_percent);
    }

    sprintf(tmp,"%s",decodedPtr);
    GG_DEBUG_PRINT("DEBUG");
     GG_DEBUG_PRINTLN(tmp);
    ret=getValue_c(tmp,";","p");
    if (ret!=NULL){
      double gaz_vol=atof(ret)/100;                                             
      GG_DEBUG_PRINT("gaz_vol:");
      GG_DEBUG_PRINTLN(gaz_vol);
      
      if (gaz_vol>1)                                   
        sendMQTTUpdate("/energy_m3/state",gaz_vol);
      else{
        sprintf(tmp,"%s",decodedPtr);
        sendMQTTUpdateStr("/payload_error/state",tmp);
      }
      gazvol_oldValue=gaz_vol;
    }
  }

  WiFiClient client = server.available();

  if (client) {
    String currentLine = "";
    while (client.connected()) { 
      
     if (client.available()) {            // if there's bytes to read from the client,
      char c = client.read();             // read a byte, then
  	  //Serial.write(c);                    // print it out the serial monitor
  	  if (c == '\n') {                    // if the byte is a newline character
                                          // if the current line is blank, you got two newline characters in a row.
                                          // that's the end of the client HTTP request, so send a response:

        if (currentLine.length() == 0) {

            // HTTP headers always start with a response code (e.g. HTTP/1.1 200 OK)
            // and a content-type so the client knows what's coming, then a blank line:

            client.println("HTTP/1.1 200 OK");
            client.println("Content-type:text/html");
            client.println();

            client.println("output gazpar log:");

            for(int i=0;i<cLog.size();i++){
              client.println((char*)cLog[i]);
            }

            // the content of the HTTP response follows the header:

            //client.print("Click <a href=\"/H\">here</a> turn the LED on pin 9 on<br>");
            //client.print("Click <a href=\"/L\">here</a> turn the LED on pin 9 off<br>");
                                                                                        
            client.println();                           // The HTTP response ends with another blank line
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

    client.stop();
    GG_DEBUG_PRINTLN("client disconnected");
  }

  //Watchdog.disable();
}
