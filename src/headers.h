#pragma once

typedef struct ip_hdr
{
	unsigned char ip_header_len : 4;
	unsigned char ip_version : 4;
	unsigned char ip_tos;
	unsigned short ip_total_length;
	unsigned short ip_id;

	unsigned char ip_frag_offset : 5;

	unsigned char ip_more_fragment : 1;
	unsigned char ip_dont_fragment : 1;
	unsigned char ip_reserved_zero : 1;

	unsigned char ip_frag_offset1;

	unsigned char ip_ttl;
	unsigned char ip_protocol;
	unsigned short ip_checksum;
	unsigned int ip_srcaddr;
	unsigned int ip_destaddr;
} IPV4_HDR;

typedef struct udp_hdr
{
	unsigned short source_port;
	unsigned short dest_port;
	unsigned short udp_length;
	unsigned short udp_checksum;
} UDP_HDR;

typedef struct tcp_header
{
	unsigned short source_port;
	unsigned short dest_port;
	unsigned int sequence;
	unsigned int acknowledge;

	unsigned char ns : 1;
	unsigned char reserved_part1 : 3;
	unsigned char data_offset : 4;

	unsigned char fin : 1;
	unsigned char syn : 1;
	unsigned char rst : 1;
	unsigned char psh : 1;
	unsigned char ack : 1;
	unsigned char urg : 1;

	unsigned char ecn : 1;
	unsigned char cwr : 1;

	unsigned short window;
	unsigned short checksum;
	unsigned short urgent_pointer;
} TCP_HDR;

typedef struct icmp_hdr
{
	BYTE type;
	BYTE code;
	USHORT checksum;
	USHORT id;
	USHORT seq;
} ICMP_HDR;