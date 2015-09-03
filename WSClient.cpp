// Author: Domingos Bruges
//
// websocket arduino client library: https://github.com/djsb/arduino-websocketclient
//
// Copyright (c) 2013 Domingos Bruges
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE. 

#include "sha1.h"
#include "Base64.h"
#include <Adafruit_CC3000.h>
#include "WSClient.h"
//#include <Ethernet.h>
#include <string.h>


bool WSClient::handshake(Client & client) {

  _client = &client;

  // If there is a connected client->
  if (_client->connected()) {
    // Check request and look for websocket handshake
    if (analyzeRequest()) {
      return true;

    } else {
      // Might just need to break until out of _client loop.
      disconnectStream();
      return false;
    }
  } else {
    return false;
  }
}

bool WSClient::analyzeRequest() {
  //bool foundupgrade = false;
  //bool foundconnection = false;
  char keyStart[17];
  char b64Key[25];
  //char key[] = "------------------------";

  //randomSeed(analogRead(0));
  randomSeed(millis() + analogRead(0));
  for (int i = 0; i < 16; ++i) {
    keyStart[i] = (char) random(1, 256);
  }

  base64_encode(b64Key, keyStart, 16);

  String key = b64Key;

//  for (int i = 0; i < 24; ++i) {
//    key[i] = b64Key[i];
//  }

  //protocol = "chat, superchat";

  _client->print(F("GET "));
  _client->print(path);
  _client->print(F(" HTTP/1.1\r\n"));
  _client->print(F("Upgrade: websocket\r\n"));
  _client->print(F("Connection: Upgrade\r\n"));
  _client->print(F("Host: "));
  _client->print(host);
  _client->print(CRLF);
  _client->print(F("Sec-WebSocket-Key: "));
  _client->print(key);
  _client->print(CRLF);
  //_client->print(F("Sec-WebSocket-Protocol: "));
  //_client->print(protocol);
  //_client->print(CRLF);
  _client->print(F("Sec-WebSocket-Version: 13\r\n"));
  _client->print(CRLF);

  // DEBUG ONLY - inspect the handshaking process
  /*
  Serial.print(F("GET "));
  Serial.print(path);
  Serial.print(F(" HTTP/1.1\r\n"));
  Serial.print(F("Upgrade: websocket\r\n"));
  Serial.print(F("Connection: Upgrade\r\n"));
  Serial.print(F("Host: "));
  Serial.print(host);
  Serial.print(CRLF);
  Serial.print(F("Sec-WebSocket-Key: "));
  Serial.print(key);
  Serial.print(CRLF);
  //Serial.print(F("Sec-WebSocket-Protocol: "));
  //Serial.print(protocol);
  //Serial.print(CRLF);
  Serial.print(F("Sec-WebSocket-Version: 13\r\n"));
  Serial.print(CRLF);
  */

  while (_client->connected() && !_client->available()) {
    // Serial.print(F("Waiting for connection and response...\r\n"));
    // Serial.print(CRLF);
    delay(50);
  }

  while (!_client->available()) {
    // Serial.print(F("Waiting for response...\r\n"));
    // Serial.print(CRLF);
    delay(50);
  }

  String line;
  String handshakeStatusHeader = "HTTP/1.1 101";

  // Check HTTP response
  line = readLine();

  if ( line.indexOf(handshakeStatusHeader) == -1 ) {
    Serial.print(F("Incorrect response: "));
    Serial.println(line);
    return false;
  }

  //int i = 0;
  //char temp[80];
  String serverKey;
  String handshakeKeyHeader = "Sec-WebSocket-Accept:";

  while ((line = readLine()) != "") {
    //Serial.println(line);
    if (line.indexOf(handshakeKeyHeader) != -1) {
      serverKey = line.substring(handshakeKeyHeader.length());
    }
  }

  // Cleanup string
  serverKey.trim();

  if (serverKey == "") {
    //Serial.println(F("No server key!"));
    return false;
  }

  //Serial.print(F("serverKey = "));
  //Serial.println(serverKey);

  String magicKey = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  char checkKey[61];

  key.concat(magicKey).toCharArray(checkKey, 61);

  //Serial.print(F("checkKey is "));
  //Serial.println(checkKey);

  uint8_t *hash;
  char result[21];
  char b64Result[28];

  Sha1.init();
  Sha1.print(checkKey);
  hash = Sha1.result();

  for (int i = 0; i < 20; ++i) {
    result[i] = (char) hash[i];
  }
  result[20] = '\0';

  //Serial.print("SHA-1 hash is ");
  //Serial.println(result);

  base64_encode(b64Result, result, 20);

  //Serial.println("compare keys");
  //Serial.println(serverKey);
  //Serial.println(b64Result);

  return serverKey.equals(b64Result);
}

String WSClient::readLine() {
    String line = "";
    char character;

    while((character = timedRead()) != '\n') {
        if (character != '\r' && character != -1) {
            line += character;
        }
    }

    return line;
}

void WSClient::disconnect() {
  disconnectStream();
}


void WSClient::disconnectStream() {
  // Should send 0x8700 to server to tell it I'm quitting here.
  _client->write((uint8_t) 0x87);
  _client->write((uint8_t) 0x00);

  _client->flush();
  delay(10);
  _client->stop();
}


char *WSClient::getData() {
  uint8_t msgtype;
  //uint8_t bite;
  unsigned int length;
  uint8_t mask[4];
  uint8_t index;
  unsigned int i;
  bool hasMask = false;

  // char array to hold bytes sent by server to client
  // message could not exceed 256 chars. Array initialized with NULL
  char socketStr[256] = {NULL};


  if (_client->connected() && _client->available()) {


    msgtype = timedRead();
    if (!_client->connected()) {
      return (char *) socketStr;
    }

    length = timedRead();

    if (length > 127) {
      hasMask = true;
      length = length & 127;
    }


    if (!_client->connected()) {
      return (char *) socketStr;
    }

    index = 6;


    if (length == 126) {
      length = timedRead() << 8;
      if (!_client->connected()) {
        return (char *) socketStr;
      }

      length |= timedRead();
      if (!_client->connected()) {
        return (char *) socketStr;
      }

    } else if (length == 127) {

      while (1) {
        // halt, can't handle this case
      }
    }


    if (hasMask) {
      // get the mask
      mask[0] = timedRead();
      if (!_client->connected()) {
        return (char *) socketStr;
      }

      mask[1] = timedRead();
      if (!_client->connected()) {
        return (char *) socketStr;
      }

      mask[2] = timedRead();
      if (!_client->connected()) {
        return (char *) socketStr;
      }

      mask[3] = timedRead();
      if (!_client->connected()) {
        return (char *) socketStr;
      }
    }


    if (hasMask) {
      for (i = 0; i < length; ++i) {
        socketStr[i] = (char) (timedRead() ^ mask[i % 4]);
        if (!_client->connected()) {
          return (char *) socketStr;
        }
      }
    } else {
      for (i = 0; i < length; ++i) {
        socketStr[i] = (char) timedRead();
        if (!_client->connected()) {
          return (char *) socketStr;
        }
      }
    }

  }

  return (char *) socketStr;
}

bool WSClient::sendData(String s) {
  // Serial.println(F("")); Serial.print(F("TX: "));
  // for (int i=0; i<strlen(str); i++)
  //     Serial.print(str[i]);
  if (_client->connected()) {
    return sendEncodedData(s);
  }

  return false;
}

int WSClient::timedRead() {
  while (!_client->available()) {
    delay(50);
  }

  int a = _client->read();
  return a;
}

bool WSClient::sendEncodedData(String s) {
  int sLen = s.length();
  int totalSize = 6 + (sLen < 126 ? 0 : sLen < ((2 ^ 16) ? 2 : 8)) + sLen;
  if (totalSize > 400) {//limited by static toSend array size
    Serial.println("string too long: ");
    Serial.println(s);
    Serial.println(totalSize);
    return false;
  }

  uint8_t toSend[totalSize];
  toSend[0] = B10000001; //FIN,RSV1,RSV2,RSV3,OPCODE(4)
  toSend[1] = B10000000 + (sLen < 126 ? sLen : ((sLen < (2 ^ 16)) ? 126 : 127)); //MASK, LEN(7)
  int i = 2;
  if (sLen < 126) {
    //don't do anything
  } else if (sLen < (2 ^ 16)) {
    toSend[2] = (uint8_t) ((sLen >> 8) & 0xff);
    toSend[3] = (uint8_t) (sLen & 0xff);
    i = 4;
  } else {
    //we should never get here, since this would mean the String is using 65k of memory
    Serial.println("shouldn't be here");
    return false;
  }

  for (unsigned int n = 0; n < 4; n++, i++) {
    toSend[i] = B00000000;//MASK_KEY(8)
  }

  for (unsigned int n = 0; n < sLen; n++, i++) {
    toSend[i] = s.charAt(n) ^ B00000000;
  }
  _client->write(toSend, totalSize);

  return true;
}


