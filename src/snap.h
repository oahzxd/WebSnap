#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

#include <string.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/ethernet.h>


/* #include <sys/types.h>   */
/* #include <netinet/in.h>   */
/* #include <arpa/inet.h>   */
/* #include <netinet/if_ether.h>   */
/* #include <net/ethernet.h>   */

#include   <sys/ioctl.h> 
#include   <netinet/in.h> 
#include   <net/if.h> 


#define MAX_STR_LEN 100

struct ip_header {
    u_int8_t  ip_vhl; 
    u_int8_t  ip_tos;
    u_int16_t ip_len;
    u_int16_t ip_id;
    u_int16_t ip_off;
    u_int8_t  ip_ttl;
    u_int8_t  ip_p;
    u_int16_t ip_sum;
    struct in_addr ip_src;
    struct in_addr ip_dst;
};  
  
struct tcp_header {  
    u_int16_t tcp_src_port;
    u_int16_t tcp_dst_port;
    u_int32_t tcp_seq;
    u_int32_t tcp_ack;
    u_int8_t  th_offx2;
    u_int8_t  th_flags;  
    u_int16_t tcp_win;
    u_int16_t tcp_sum;
    u_int16_t tcp_urp;
};  

struct Stream_id {
    char ip_port1[50];
    char ip_port2[50];
    FILE* fd;
    int stream_id;
};


#define True 1
#define False 0
#define MAX_FRAME_LEN (1024 * 16)
#define MAX_STREAM_NUM 500

struct Stream_id stream_id_arr[MAX_STREAM_NUM];

typedef struct _tcp_stream_id {
    u_char mac_src[32];
    u_char mac_dst[32];
    char ip_src[64];
    char ip_dst[64];
    unsigned short port_src;
    unsigned short port_dst;
} Tcp_Stream_Id;

typedef struct _tcp_node {
    int is_ack;
    int syn;
    int fin;
    unsigned long seq;
    int len;
    struct _tcp_node *prev;
    struct _tcp_node *next;
    struct _tcp_node *ack_node_head;
    int ack_len;
    unsigned char data[MAX_FRAME_LEN];
} Tcp_Node;

typedef struct _tcp_list {
    Tcp_Stream_Id id;
    Tcp_Node node_head;
    struct _tcp_list *next;
}
