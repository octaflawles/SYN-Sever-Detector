#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <time.h>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#define MAX_REC 1024
#define SYN_LIMIT 20
#define TIME_WINDOW 5

typedef struct
{
    char src_ip[16];
    unsigned short dst_port;
    int syn_count;
    time_t first_time;
} syn_stat;

syn_stat table[MAX_REC];
int table_count = 0;
char local_ip[16];

void get_local_ip()
{
    IP_ADAPTER_ADDRESSES *addr, *cur;
    ULONG size = 0;

    GetAdaptersAddresses(AF_INET, 0, NULL, NULL, &size);
    addr = (IP_ADAPTER_ADDRESSES *)malloc(size);
    GetAdaptersAddresses(AF_INET, 0, NULL, addr, &size);

    for (cur = addr; cur; cur = cur->Next)
    {
        IP_ADAPTER_UNICAST_ADDRESS *u = cur->FirstUnicastAddress;
        if (u && u->Address.lpSockaddr->sa_family == AF_INET)
        {
            struct sockaddr_in *sa =
                (struct sockaddr_in *)u->Address.lpSockaddr;
            if (strcmp(inet_ntoa(sa->sin_addr), "127.0.0.1") != 0)
            {
                strcpy(local_ip, inet_ntoa(sa->sin_addr));
                break;
            }
        }
    }
    free(addr);
}

int find_stat(const char *ip, unsigned short port)
{
    for (int i = 0; i < table_count; i++)
    {
        if (!strcmp(table[i].src_ip, ip) &&
            table[i].dst_port == port)
            return i;
    }
    return -1;
}

void packet_handler(u_char *param,
                    const struct pcap_pkthdr *header,
                    const u_char *pkt_data)
{

    struct iphdr *ip =
        (struct iphdr *)(pkt_data + 14);

    if (ip->protocol != IPPROTO_TCP)
        return;

    struct tcphdr *tcp =
        (struct tcphdr *)((u_char *)ip + ip->ihl * 4);

    struct in_addr dst;
    dst.S_un.S_addr = ip->daddr;

    if (strcmp(inet_ntoa(dst), local_ip) != 0)
        return;

    if ((tcp->th_flags & TH_SYN) &&
        !(tcp->th_flags & TH_ACK))
    {

        struct in_addr src;
        src.S_un.S_addr = ip->saddr;

        char src_ip[16];
        strcpy(src_ip, inet_ntoa(src));

        unsigned short port = ntohs(tcp->th_dport);
        time_t now = time(NULL);

        int idx = find_stat(src_ip, port);
        if (idx == -1)
        {
            strcpy(table[table_count].src_ip, src_ip);
            table[table_count].dst_port = port;
            table[table_count].syn_count = 1;
            table[table_count].first_time = now;
            table_count++;
        }
        else
        {
            if (difftime(now, table[idx].first_time) > TIME_WINDOW)
            {
                table[idx].syn_count = 1;
                table[idx].first_time = now;
            }
            else
            {
                table[idx].syn_count++;
            }

            if (table[idx].syn_count >= SYN_LIMIT)
            {
                printf(
                    "syn flood src=%s dst=%s port=%d syn=%d time=%d\n",
                    src_ip,
                    local_ip,
                    port,
                    table[idx].syn_count,
                    TIME_WINDOW);
            }
        }
    }
}

int main()
{
    pcap_if_t *alldevs, *d;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    get_local_ip();
    if (strlen(local_ip) == 0)
    {
        printf("no local ip\n");
        return 1;
    }

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        printf("pcap error\n");
        return 1;
    }

    d = alldevs;
    handle = pcap_open_live(d->name, 65536, 1, 1000, errbuf);
    if (!handle)
    {
        printf("open error\n");
        return 1;
    }

    printf("monitor ip=%s\n", local_ip);

    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}
