#include "horus.h"

FILE* logfile;
int tcp = 0, udp = 0, icmp = 0, others = 0, igmp = 0, total = 0, i, j;
sockaddr_in source, dest;
char hex[2];

int main(int argc, char* argv[])
{
	if (argc < 3) {
		cout << "Usage:" << endl << "horus [IP] [logfile]" << endl;
		return 0;
	}

	SOCKET sniffer;
	int in = -1;

	WSADATA wsa;

	logfile = fopen(argv[2], "w");
	if (logfile == NULL)
	{
		cout << "Error creating logfile. Maybe try making it manually then run again?" << endl;
		return 1;
	}

	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		cout << "Error initialising Winsock." << endl;
		return 1;
	}

	sniffer = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	if (sniffer == INVALID_SOCKET)
	{
		cout << "Please run horus as an administrator" << endl;
		return 1;
	}

	dest.sin_family = AF_INET;
	dest.sin_port = 0;
	dest.sin_addr.s_addr = inet_addr(argv[1]);

	if (bind(sniffer, (struct sockaddr*)&dest, sizeof(dest)) == SOCKET_ERROR)
	{
		cout << "You don't own the IP specified. This packet sniffer can only sniff local packets, because otherwise it would be illegal. Sorry! :)" << endl;
		return 1;
	}

	int j = 1;
	if (WSAIoctl(sniffer, SIO_RCVALL, &j, sizeof(j), 0, 0, (LPDWORD)&in, 0, 0) == SOCKET_ERROR)
	{
		cout << "Error setting promicious mode. Maybe you network interface is broken?" << endl;
		return 1;
	}

	cout << "Stats:" << endl;
	StartSniffing(sniffer);

	closesocket(sniffer);
	WSACleanup();

	return 0;
}

void StartSniffing(SOCKET sniffer)
{
	char* Buffer = (char*)malloc(65536);
	int mangobyte;

	if (Buffer == NULL)
	{
		cout << "Error alocating memory. Maybe all your RAM is in use?" << endl;
		return;
	}

	do
	{
		mangobyte = recvfrom(sniffer, Buffer, 65536, 0, 0, 0);

		if (mangobyte > 0)
		{
			ProcessPacket(Buffer, mangobyte);
		}
		else
		{
			cout << "Error recieving from network interface. Maybe it's broken?" << endl;
			return;
		}
	} while (mangobyte > 0);

	free(Buffer);
}

void ProcessPacket(char* Buffer, int Size)
{
	IPV4_HDR* iphdr = (IPV4_HDR*)Buffer;
	++total;

	switch (iphdr->ip_protocol)
	{
	case 1:
		++icmp;
		PrintIcmpPacket(Buffer, Size, logfile);
		break;
	case 2:
		PrintIgmpPacket(Buffer, Size, logfile);
		++igmp;
		break;
	case 6:
		++tcp;
		PrintTcpPacket(Buffer, Size, logfile);
		break;
	case 17:
		++udp;
		PrintUdpPacket(Buffer, Size, logfile);
		break;
	default:
		++others;
		break;
	}
	printf("TCP : %d UDP : %d ICMP : %d IGMP : %d Others : %d Total : %d\r", tcp, udp, icmp, igmp, others, total);
}

void PrintData(char* data, int Size)
{
	char a, line[17];

	for (i = 0; i < Size; i++)
	{
		a = (unsigned char)data[i];

		line[i % 16] = a;
		if ((i != 0 && (i + 1) % 16 == 0) || i == Size - 1)
		{
			line[i % 16 + 1] = '\0';
			fprintf(logfile, "%s", line);
		}
	}

	fprintf(logfile, "\n");
}