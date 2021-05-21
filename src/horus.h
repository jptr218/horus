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

void process(char*, int);
void printIgmp(char* Buffer, int size, FILE* log);
void printIcmp(char*, int, FILE* log);
void printUdp(char*, int, FILE* log);
void printTcp(char*, int, FILE* log);
void print(char*, int);
