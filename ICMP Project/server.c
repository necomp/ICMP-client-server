/* server.c */
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <stdio.h>
#include <pcap.h>
#include <winsock2.h>
#include <time.h>
#include <locale.h>

#pragma comment(lib, "ws2_32.lib")


#define SERVER_IP_STR "192.168.1.112"  
// ------------------------------------------------------------
int tracert_uzaklik = 0; 	// Tracert için isteğe göre uzaklık değişitirilebilir. 
							// Program başladığında kullanıcıdan değer alıncak
typedef struct { unsigned char d[6]; unsigned char s[6]; unsigned short t; } EthH;
typedef struct { unsigned char v_hl; unsigned char tos; unsigned short l; unsigned short i; unsigned short f; unsigned char ttl; unsigned char p; unsigned short c; unsigned int src; unsigned int dst; } IPH;
typedef struct { unsigned char t; unsigned char c; unsigned short chk; unsigned short i; unsigned short s; } ICMPH;

unsigned short checksum(unsigned short *b, int len) {
    unsigned long sum = 0;
    while (len > 1) { sum += *b++; len -= 2; }
    if (len == 1) sum += *(unsigned char *)b;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

// Flood kontrolü için global değişkenler
time_t son_paket_zamani = 0;
int paket_sayaci = 0;

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    pcap_t *fp = (pcap_t *)param;
    unsigned char packet[200];
    int len = header->len > 200 ? 200 : header->len;
    memcpy(packet, pkt_data, len);

    EthH *eth = (EthH *)packet;
    if (ntohs(eth->t) != 0x0800) return; // Sadece IP

    IPH *ip = (IPH *)(packet + 14);
    if (ip->p != 1) return; // Sadece ICMP

    ICMPH *icmp = (ICMPH *)(packet + 34);
    if (icmp->t != 8) return; // Sadece Request

    printf("\n[Paket Yakalandi] Analiz Basliyor...\n");

    int hata_tipi = 0; // 0 = Hata Yok (Echo Reply)
    int hata_kodu = 0;

    // 1. PARAMETER PROBLEM (Bozuk Başlık Kontrolü)
    if (ip->v_hl != 0x45) {
        printf(" -> TESPIT: Bozuk IP Basligi (0x%X). IPv4 degil!\n", ip->v_hl);
        hata_tipi = 12; // Parameter Problem
        hata_kodu = 0;
    }
    // 2. TIME EXCEEDED (TTL Kontrolü)
    else if (ip->ttl <= 1) {
        printf(" -> TESPIT: TTL Suresi Doldu (%d)!\n", ip->ttl);
        hata_tipi = 11; // Time Exceeded
        hata_kodu = 0;
    }
    // 3. SOURCE QUENCH (Flood Kontrolü)
    else if (difftime(time(NULL), son_paket_zamani) < 1) {
        paket_sayaci++;
        if (paket_sayaci > 10) {
            printf(" -> TESPIT: Flood Saldirisi! (Source Quench)\n");
            hata_tipi = 4; // Source Quench
            hata_kodu = 0;
        }
    } else {
        son_paket_zamani = time(NULL);
        paket_sayaci = 0;
    }

    // 4. DESTINATION UNREACHABLE (IP Adresi Kontrolü)
    unsigned int my_ip_addr = inet_addr(SERVER_IP_STR);
    if (hata_tipi == 0 && ip->dst != my_ip_addr) {
        // 5. REDIRECT (8.8.8.8 ise Yönlendir)
        struct in_addr hedef_ip_struct;
        hedef_ip_struct.s_addr = ip->dst;
        if (strcmp(inet_ntoa(hedef_ip_struct), "8.8.8.8") == 0) {
            printf(" -> TESPIT: Google DNS'e gidiyor. Yonlendirme (Redirect) gerekli.\n");
            hata_tipi = 5; // Redirect
            hata_kodu = 1; // Redirect for Host
        } else {
            printf(" -> TESPIT: Yanlis IP Adresi (%s). Hedefe Ulasilamaz!\n", inet_ntoa(hedef_ip_struct));
            hata_tipi = 3; // Dest Unreachable
            hata_kodu = 1; // Host Unreachable
        }
    }
	
	char sahte_router_ip[20];
    int tracert_modu = 0;
	
	if (ip->ttl >= 1 && ip->ttl <= tracert_uzaklik) {
        sprintf(sahte_router_ip, "10.0.0.%d", ip->ttl);
        hata_tipi = 11; // Time Exceeded
        hata_kodu = 0;
        tracert_modu = 1;
    }else {
        tracert_modu=0;
    }

    // --- CEVAP HAZIRLAMA ---
    unsigned char tmpM[6]; memcpy(tmpM, eth->s, 6); memcpy(eth->s, eth->d, 6); memcpy(eth->d, tmpM, 6);
	ip->dst = ip->src; 					// Sunucuya gelen paketten source ip alınıp yeni gönderilecek olan paketin hedefi yapılıyor	
	if (tracert_modu == 1) {     
        ip->src = inet_addr(sahte_router_ip); 
    } else {
        ip->src = inet_addr(SERVER_IP_STR);	// Kaynak ip artık server İP
    }

    icmp->t = hata_tipi;
    icmp->c = hata_kodu;

    // Checksum Hesapla
    ip->c = 0; ip->c = checksum((unsigned short *)ip, 20);
    icmp->chk = 0; icmp->chk = checksum((unsigned short *)icmp, 8 + 10);

    if (pcap_sendpacket(fp, packet, len) != 0) {
        printf("Paket gonderilemedi: %s",pcap_geterr(fp));
    } else {
        if (hata_tipi == 0) printf(" -> Echo Reply (Normal) Gonderildi.\n");
        else printf(" -> HATA MESAJI (Type: %d, Code: %d) Gonderildi!\n", hata_tipi, hata_kodu);
    }
}

int main() {
    setlocale(LC_ALL, "Turkish");
    pcap_if_t *alldevs, *d;
    char err[PCAP_ERRBUF_SIZE];
    pcap_t *fp;
    int i=0, inum;

    // 1. KART SECME EKRANI
    if (pcap_findalldevs(&alldevs, err) == -1) { printf("Hata: %s\n", err); return 1; }
    
    printf("\n--- SUNUCU ICIN AG KARTLARI ---\n");
    for(d=alldevs; d; d=d->next) {
        printf("%d. %s\n", ++i, d->description ? d->description : "Isimsiz");
    }
    if(i==0) { printf("Kart bulunamadi!\n"); return 1; }

    printf("Dinlenecek Karti Secin (1-%d): ", i);
    scanf("%d", &inum);
	
	printf("Tracert icin server sunucu arasi uzaklik secin(max 30): ");
	scanf("%d", &tracert_uzaklik);
	
    for(d=alldevs, i=0; i< inum-1; d=d->next, i++);
    
    printf("AKILLI SUNUCU BASLATILDI\n");
    printf("Dinlenen: %s\n", d->description);
    printf("Bekleniyor...\n");

    fp = pcap_open_live(d->name, 65536, 1, 1000, err);
    if (!fp) { printf("Acilamadi!\n"); return 1; }
    
    pcap_loop(fp, 0, packet_handler, (u_char *)fp);
    
    return 0;
}