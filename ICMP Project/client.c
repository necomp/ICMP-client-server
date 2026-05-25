/* client.c */
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <stdio.h>
#include <pcap.h>
#include <winsock2.h>
#include <locale.h>
#include <process.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib") 


#define SERVER_IP "192.168.1.112" 	// Sunucunun IP Adresi 
#define MY_IP "192.168.1.100"		// IP
// ----------------------------------

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

// Paket Hazırlama 
void paket_hazirla(unsigned char *pkt, int ttl, const char *dest_ip, int bozuk_baslik_modu, unsigned short pid, int seq) {
    EthH *eth = (EthH *)pkt;
    IPH *ip = (IPH *)(pkt + 14);
    ICMPH *icmp = (ICMPH *)(pkt + 34);

    // Ethernet (Broadcast)
    memset(eth->d, 0xFF, 6);
    
    //unsigned char MyMAC[6] = {0x58,0x11,0x22,0x3a,0x7d,0xc6}; 
	unsigned char MyMAC[6] = {0x9c,0x2f,0x9d,0xa2,0x3e,0x25}; // Necib MAC
    memcpy(eth->s, MyMAC, 6);
    eth->t = htons(0x0800);

    // IP Basligi
    if (bozuk_baslik_modu == 1) ip->v_hl = 0x99; // Bozuk Baslik
    else ip->v_hl = 0x45; // Normal

    ip->ttl = ttl;
    ip->p = 1; // ICMP
    ip->l = htons(sizeof(IPH) + sizeof(ICMPH) + 10);
    ip->src = inet_addr(MY_IP);
    ip->dst = inet_addr(dest_ip);
    ip->c = 0; ip->c = checksum((unsigned short *)ip, 20);

    // ICMP
    icmp->t = 8; // Echo Request
    icmp->c = 0;
    icmp->i = htons(pid);
    icmp->s = htons(seq);
    icmp->chk = 0; icmp->chk = checksum((unsigned short *)icmp, 8 + 10);
    
    memcpy(pkt + 42, "TEST_DATA!", 10);
}

// Cevap Analizi
void icmp_analiz_et(ICMPH *icmp, IPH *ip) {
    struct in_addr gonderen; gonderen.s_addr = ip->src;
    printf("\n[!] CEVAP GELDI [!]\n");
    printf("    -> Gonderen: %s\n", inet_ntoa(gonderen));
    
    if (icmp->t == 0) printf("    -> DURUM: Normal Cevap (Ping Basarili)\n");
    else if (icmp->t == 3) printf("    -> HATA: Destination Unreachable (Hedef Ulasilamaz)\n");
    else if (icmp->t == 4) printf("    -> HATA: Source Quench (Yavasla!)\n");
    else if (icmp->t == 5) printf("    -> BILGI: Redirect (Yonlendirme)\n");
    else if (icmp->t == 11) printf("    -> HATA: Time Exceeded (TTL Suresi Bitti)\n");
    else if (icmp->t == 12) printf("    -> HATA: Parameter Problem (Bozuk Baslik)\n");
    else printf("    -> BILGI: Bilinmeyen ICMP Tipi (%d)\n", icmp->t);
	printf("    -> ICMP | Type: %d | Code: %d |\n", icmp->t,icmp->c);
    printf("------------------------------------------------\n");
}

// Paket Bekleme (Timeout'lu)
void paket_yakala(pcap_t *fp, unsigned short pid) {
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    int res;
    time_t start = time(NULL);
    
    printf(" -> Cevap bekleniyor...\n");
    while(time(NULL) - start < 3) { // 3 Saniye bekle
        res = pcap_next_ex(fp, &header, &pkt_data);
        if(res > 0) {
            EthH *eth = (EthH *)pkt_data;
            if (ntohs(eth->t) != 0x0800) continue;
            IPH *ip = (IPH *)(pkt_data + 14);
            if (ip->p != 1) continue;
            ICMPH *icmp = (ICMPH *)(pkt_data + 34);
            
            if (icmp->t == 8) continue; // Kendi istegimiz
            
            // Cevap sunucudan mi?
            if (htons(pid) == icmp->i ) {
                icmp_analiz_et(icmp, ip);
                return;
            }
        }
    }
    printf(" -> Zaman asimi! (Sunucu cevap vermedi veya paket kayboldu)\n");
}

// PCAP tamponunda kalan eski paketleri temizler
void buffer_temizle(pcap_t *fp) {
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    int res;
    printf("Buffer temizleniyor ....\n");
    while((res = pcap_next_ex(fp, &header, &pkt_data)) > 0) {
        // Okunan paketi cope atiyoruz
    }
	printf("Buffer temizlendi\n");
}

int main() {
    setlocale(LC_ALL, "Turkish");
    unsigned short pid = (unsigned short)(_getpid() & 0xFFFF);
    pcap_if_t *alldevs, *d;
    char err[PCAP_ERRBUF_SIZE];
    pcap_t *fp;
    unsigned char packet[100]= {0};
    int i=0, inum;

    // 1. KART SECME EKRANI
    if (pcap_findalldevs(&alldevs, err) == -1) { printf("Hata: %s\n", err); return 1; }
    
    printf("\n--- AG KARTLARI LISTESI ---\n");
    for(d=alldevs; d; d=d->next) {
        printf("%d. %s\n", ++i, d->description ? d->description : "Isimsiz");
    }
    if(i==0) { printf("Kart bulunamadi!\n"); return 1; }

    printf("Seciminiz (1-%d): ", i);
    scanf("%d", &inum);

    for(d=alldevs, i=0; i< inum-1; d=d->next, i++);
    fp = pcap_open_live(d->name, 65536, 1, 1000, err);
    if (!fp) { printf("Acilamadi!\n"); return 1; }
    printf("Baglandi: %s\n", d->description);

    // 2. MENU DONGUSU
    int secim;
    do {
		
		system("cls");
        printf("\n=== HATA SENARYOLARI TEST MENUSU ===\n");
        printf("1. Normal Ping At\n");
        printf("2. Time Exceeded Testi (TTL=1)\n");
        printf("3. Dest Unreachable Testi (Yanlis IP)\n");
        printf("4. Parameter Problem Testi (Bozuk Header)\n");
        printf("5. Source Quench Testi (Flood)\n");
        printf("6. Redirect Testi (8.8.8.8)\n");
        printf("7. Tracert (192.168.1.112)\n");
        printf("0. Cikis\n");
        printf("Secim: ");
        scanf("%d", &secim);

        if (secim == 1) { // Normal
            paket_hazirla(packet, 64, SERVER_IP, 0, pid, 1);
            pcap_sendpacket(fp, packet, 52);
            paket_yakala(fp, pid);
        }
        else if (secim == 2) { // TTL=1
            paket_hazirla(packet, 1, SERVER_IP, 0, pid, 1);
            pcap_sendpacket(fp, packet, 52);
            paket_yakala(fp, pid);
        }
        else if (secim == 3) { // Yanlis IP
            paket_hazirla(packet, 64, "10.10.10.10", 0, pid, 1);
            pcap_sendpacket(fp, packet, 52);
            paket_yakala(fp, pid);
        }
        else if (secim == 4) { // Bozuk Header
            paket_hazirla(packet, 64, SERVER_IP, 1, pid, 1);
            pcap_sendpacket(fp, packet, 52);
            paket_yakala(fp, pid);
        }
        else if (secim == 5) { // Flood
            printf(" -> 20 Paket hizlica gonderiliyor...\n");
            for(int k=0; k<20; k++) {
                paket_hazirla(packet, 64, SERVER_IP, 0, pid, k);
                pcap_sendpacket(fp, packet, 52);
                Sleep(10);
            }
            paket_yakala(fp, pid);
        }
        else if (secim == 6) { // Redirect
            paket_hazirla(packet, 64, "8.8.8.8", 0, pid, 1);
            pcap_sendpacket(fp, packet, 52);
            paket_yakala(fp, pid);
        }
		else if (secim == 7) { // TTL=1
            printf(" -> Tracert Basliyor...\n");
			int hedefe_ulasilmadi = 1; // ttl değeri olarak kullanılıcak ve hedef bulunduğunda 0 yapılıp döngüden çıkılıcak
			while(hedefe_ulasilmadi && hedefe_ulasilmadi <=30){
				paket_hazirla(packet, hedefe_ulasilmadi , SERVER_IP, 0, pid, 1);
				hedefe_ulasilmadi ++ ; // ttl değeri olarak kullanıldığı için 1 arttırılıyor
				pcap_sendpacket(fp, packet, 52);
				
				struct pcap_pkthdr *header;
				const u_char *pkt_data;
				int res;
				time_t start = time(NULL);
				
				int paket_geldi= 0 ;
				printf(" -> Cevap bekleniyor...\n");
				while(time(NULL) - start < 3) { // 3 Saniye bekle
					res = pcap_next_ex(fp, &header, &pkt_data);
					if(res > 0) {
						EthH *eth = (EthH *)pkt_data;
						if (ntohs(eth->t) != 0x0800) continue;
						IPH *ip = (IPH *)(pkt_data + 14);
						if (ip->p != 1) continue;
						ICMPH *icmp = (ICMPH *)(pkt_data + 34);
						
						if (icmp->t == 8) continue; // Kendi istegimiz
						
						// Cevap sunucudan mi?
						if (htons(pid) == icmp->i ) {
							icmp_analiz_et(icmp, ip);
							paket_geldi = 1;
							if (icmp->t == 0) {
								printf(" [!!!] HEDEFE ULASILDI [!!!]\n");
								hedefe_ulasilmadi = 0; 
								
							}		
							break;
						}
						
					}
				}
				if (paket_geldi == 0) printf(" -> Zaman asimi! (Sunucu cevap vermedi veya paket kayboldu)\n");
			}
			if (hedefe_ulasilmadi== 31) printf(" -> Hedef IP ye ulasilamadi!\n");
			
        }
		buffer_temizle(fp);
		printf("Devam etmek icin bir tusa basiniz..\n");getchar();getchar();
		

    } while (secim != 0);

    pcap_close(fp);
    return 0;
}