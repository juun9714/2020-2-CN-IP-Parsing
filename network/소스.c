#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <math.h>
#include <WinSock2.h>
#include <time.h>
#pragma comment(lib,"ws2_32")
#define MAX_PACKET 500
#define MAC_ADDR 6
#define DF(frag) (frag & 0x40)
#define MF(frag) (frag & 0x20)
#define FRAG_OFFSET(frag) (ntohs(frag) & (~0x6000))

//struct
//Structs
typedef struct pcapHeader {
    int magic;
    short major;
    short minor;
    int time_zone;
    int time_stamp;
    int snap_len;
    int link_type;
}pcap_H;

typedef struct Timeval_ {
    long val_sec;
    long val_usec;
}Timeval;

typedef struct pktHeader_ {
    Timeval time;
    unsigned int caplen;
    unsigned int len;
}pkt_H;

typedef struct Mac {
    unsigned char MAC_DST[MAC_ADDR];
    unsigned char MAC_SRC[MAC_ADDR];
    unsigned short type;
}Mac;

typedef struct IP {
    unsigned char ver_hlen;
    unsigned char ecn;
    unsigned short tot;
    unsigned short id;
    unsigned short frag;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short checksum;
    unsigned char src_ip[4];
    unsigned char dst_ip[4];
}IP;

//Functions
void Parse(FILE* fp);
void Parse_strt(FILE* fp);
void showFileHeader(pkt_H* ph);
void showMac(Mac mac);
unsigned short ntohs_(unsigned short value);
void showIP(IP ip);

//전역
pkt_H packetHeader[MAX_PACKET];
int packetCount = 0;

int main() {
    FILE* fp;
    fp = fopen("packet3.pcap", "rb");
    Parse_strt(fp);
    fclose(fp);
    return 0;
}

void Parse_strt(FILE* fp) {
    //pcap의 쓸모없는 부분(24byte) 제거 -> 각 패킷의 TCP 헤더(MAC, Type) 읽기
    pcap_H noUse;
    fread(&noUse, sizeof(pcap_H), 1, fp);
    Parse(fp);
}

void Parse(FILE* fp) {
    pkt_H* ph = packetHeader;
    //fp가 끝날 때까지 읽기 

    while (feof(fp) == 0) {
        if ((fread(ph, sizeof(pkt_H), 1, fp) != 1))
            break;
        if (packetCount == MAX_PACKET)
            break;

        //패킷이 아직 있는 경우 -> time, caplen, actual len 출력
        showFileHeader(ph);
        Mac mac;
        fread(&mac, sizeof(mac), 1, fp);
        showMac(mac);
        char tmpIP[65536];
        //caplen-(mac address and type which are 14 bytes)
        fread(tmpIP, ph->caplen - 14, 1, fp);
        IP* ip = (IP*)tmpIP;
        showIP(*ip);
    }
}



void showFileHeader(pkt_H* ph) {
    packetCount++;

    time_t rawtime = ph->time.val_sec;
    //time_t rawtime2 = ph->time.val_usec;
    struct tm  ts;
    //struct tm  ts2;
    char buf[80];
    //char buf2[80];

    // Format time, "ddd yyyy-mm-dd hh:mm:ss zzz"
    ts = *localtime(&rawtime);
    strftime(buf, sizeof(buf), "%a %Y-%m-%d %H:%M:%S", &ts); 
    //printf("%s\n\n", buf);

    printf("\n\n<Packet %d> \nLocal Time: %s.%08d\nCaptured Packet Length: %u bytes,   Actual Packet Length: %u bytes\n",
        packetCount,buf, ph->time.val_usec, ph->caplen, ph->len);
}

void showMac(Mac mac) {
    int s, d;
    //src
    printf("SRC MAC address: ");
    for (s = 0; s < MAC_ADDR - 1; s++)
        printf("%02x:", mac.MAC_SRC[s]);
    printf("%02x ->  ", mac.MAC_SRC[s]);

    //dst
    printf("DST MAC address: ");
    for (d = 0; d < MAC_ADDR - 1; d++)
        printf("%02x:", mac.MAC_DST[d]);
    printf("%02x\n", mac.MAC_DST[d]);
}

void showIPaddr(IP ip) {
    //src
    int s, d;
    printf("SRC IP address : ");
    for (s = 0; s < 3; s++)
        printf("%u.", ip.src_ip[s]);
    printf("%u ->  ", ip.src_ip[s]);

    //dst
    printf("DST IP address : ");
    for (d = 0; d < 3; d++)
        printf("%u.", ip.dst_ip[d]);
    printf("%u\n", ip.dst_ip[d]);
}

void ver_hlen(unsigned char ver_hlen) {
    printf("Ver: %x,  ", ver_hlen >> 4);
    unsigned char tmp = ver_hlen << 4;//하위 4비트를 상위 4비트로 올렸다가
    printf("HLEN in header: %d byte\n", (tmp >> 4) * 4);//상위 4비트를 다시 하위 4비트로 내림 0000xxxx
}

void showIP(IP ip) {

    showIPaddr(ip);//IP address
    printf("Total LEN: %u byte,  ", ntohs(ip.tot)); //Total Length
    printf(" TTL: %d\n", ip.ttl); //Time to Live
    ver_hlen(ip.ver_hlen);//Version and HLEN
    printf("Id: %d,   ", ntohs(ip.id)); //Identification
    //Flag
    if (DF(ip.frag))
        printf("DF=1,   ");
    else {
        if (MF(ip.frag) == 0)
            printf("DF=0 and MF=0,   ");
        else
            printf("DF=0 and MF=1,   ");
    }
    printf("Fragment Offset: %d\n", 8 * (ntohs(ip.frag) & 0x1fff));

    //Protocol
    switch (ip.protocol) {
    case 1: printf("Protocol: ICMP. "); break;
    case 2: printf("Protocol: IGMP. "); break;
    case 6: printf("Protocol: TCP. "); break;
    case 17: printf("Protocol: UDP. "); break;
    case 89: printf("Protocol: OSPF. "); break;
    default: printf("This protocol is not supported. "); break;
    }
}


