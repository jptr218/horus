#include "horus.h"

void printIgmp(char* Buffer, int size, FILE* log) {
	sockaddr_in dest;
	IPV4_HDR* iphdr = (IPV4_HDR*)Buffer;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iphdr->ip_destaddr;

	fprintf(log, "--IGMP-->%s\n", inet_ntoa(dest.sin_addr));
}

void printTcp(char* Buffer, int Size, FILE* log)
{
	unsigned short iphdrlen;
	sockaddr_in dest;
	IPV4_HDR* iphdr = (IPV4_HDR*)Buffer;
	iphdrlen = iphdr->ip_header_len * 4;
	TCP_HDR* tcpheader = (TCP_HDR*)(Buffer + iphdrlen);

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iphdr->ip_destaddr;

	fprintf(log, "%u--TCP-->%s:%u\n", ntohs(tcpheader->source_port), inet_ntoa(dest.sin_addr), ntohs(tcpheader->dest_port));
	PrintData(Buffer + iphdrlen + tcpheader->data_offset * 4, (Size - tcpheader->data_offset * 4 - iphdr->ip_header_len * 4));
	fprintf(log, "\n");
}

void printUdp(char* Buffer, int Size, FILE* log)
{
	unsigned short iphdrlen;
	sockaddr_in dest;
	IPV4_HDR* iphdr = (IPV4_HDR*)Buffer;
	iphdrlen = iphdr->ip_header_len * 4;
	UDP_HDR* udpheader = (UDP_HDR*)(Buffer + iphdrlen);

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iphdr->ip_destaddr;

	fprintf(log, "%u--UDP-->%s:%u\n", ntohs(udpheader->source_port), inet_ntoa(dest.sin_addr), ntohs(udpheader->dest_port));
	PrintData(Buffer + iphdrlen + sizeof(UDP_HDR), (Size - sizeof(UDP_HDR) - iphdr->ip_header_len * 4));
	fprintf(log, "\n");
}

void printIcmp(char* Buffer, int Size, FILE* log)
{
	unsigned short iphdrlen;
	sockaddr_in dest;
	IPV4_HDR* iphdr = (IPV4_HDR*)Buffer;
	iphdrlen = iphdr->ip_header_len * 4;
	ICMP_HDR* icmpheader = (ICMP_HDR*)(Buffer + iphdrlen);

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iphdr->ip_destaddr;

	fprintf(log, "--ICMP-->%s\n", inet_ntoa(dest.sin_addr));
	PrintData(Buffer + iphdrlen + sizeof(ICMP_HDR), (Size - sizeof(ICMP_HDR) - iphdr->ip_header_len * 4));
	fprintf(log, "\n");
}
