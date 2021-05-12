#pragma once

#pragma comment(lib, "ws2_32.lib")

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <winsock2.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <time.h>
#include <iostream>
#include <mstcpip.h>
using namespace std;

#include "headers.h"

void StartSniffing(SOCKET Sock);

void ProcessPacket(char*, int);
void PrintIgmpPacket(char* Buffer, int size, FILE* log);
void PrintIcmpPacket(char*, int, FILE* log);
void PrintUdpPacket(char*, int, FILE* log);
void PrintTcpPacket(char*, int, FILE* log);
void PrintData(char*, int);