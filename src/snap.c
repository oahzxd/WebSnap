#include "snap.h"

#define DEBUG 1

#ifdef DEBUG
#define DbgPrintf printf
#else
#define DbgPrintf /\
/DbgPrintf
#endif

Tcp_List tcp_list_head;

int get_linux_mac_address(char *mac_addr, const char *if_name)
{
    struct ifreq ifreq;
    int sock;
    if ((sock = socket(AF_INET,SOCK_STREAM,0)) < 0)
    {
        perror("socket");
        return -1;
    }
    strcpy(ifreq.ifr_name, if_name);
    if (ioctl(sock, SIOCGIFHWADDR, &ifreq) < 0)
    {
        perror("ioctl");
        return -1;
    }
    sprintf(mac_addr, "%02x:%02x:%02x:%02x:%02x:%02x",
            (u_char) ifreq.ifr_hwaddr.sa_data[0],
            (u_char) ifreq.ifr_hwaddr.sa_data[1],
            (u_char) ifreq.ifr_hwaddr.sa_data[2],
            (u_char) ifreq.ifr_hwaddr.sa_data[3],
            (u_char) ifreq.ifr_hwaddr.sa_data[4],
            (u_char) ifreq.ifr_hwaddr.sa_data[5]);
    return 0;
}


Tcp_List* create_tcp_list(Tcp_Stream_Id id)
{
    Tcp_List *new_list = malloc(sizeof(Tcp_List));
    Tcp_List *tmp = tcp_list_head.next;
    memset(new_list, 0, sizeof(Tcp_List));
    new_list->id = id;
    tcp_list_head.next = new_list;
    new_list->next = tmp;
    return new_list;
}

int is_list_complete(Tcp_Node *head)
{
    if (head->next == NULL)
        return False;
    
    Tcp_Node *pt = head;
    unsigned long next_seq = head->next->seq;
    int is_complete = True;
    int total_size = 0;
    do {
        pt = pt->next;
        printf("pt->seq=%ul, next_seq=%ul, len=%d, is_ack=%d\n", pt->seq, next_seq, pt->len, pt->is_ack);
        if (pt->seq != next_seq) {
            is_complete = False;
            break;
        }
        if (pt->len == 0) {
            next_seq = pt->seq + 1;
        } else {
            next_seq = pt->seq + pt->len;
        }
        total_size += pt->len;
    } while (pt->next != NULL);
    printf("------------------\n");
    if (is_complete == True) {
        if (pt->fin == 1) {
            if (total_size == 0) {
                return False;
            }
            return True;
        }
    }
    return False;
}

void write_list(Tcp_Node *head)
{
    static int name = 1;
    Tcp_Node *pnode = NULL;
    char filename[8] = {0};
    snprintf(filename, 8, "tmp%d", name++);
    FILE *fd  = fopen(filename, "a+");
    for (pnode = head->next; pnode != NULL; pnode = pnode->next) {
        char sign[50] = {0};
        if (pnode->ack_len != 0) {
            snprintf(sign, 50, "\r\n\r\n--[len=%d]--\r\n\r\n", pnode->ack_len);
            fwrite(sign, 1, strlen(sign), fd);
        }
        fwrite(pnode->data, 1, pnode->len, fd);

        
        printf("********pnode->ack_len=%d****************\n", pnode->ack_len);
        is_list_complete(pnode->ack_node_head);
        printf("************************^^^^^^^^^^^^^^^^^^\n");
        Tcp_Node *anode = NULL;
        for (anode = pnode->ack_node_head->next; anode != NULL; anode = anode->next) {
            fwrite(anode->data, 1, anode->len, fd);
        }
    }
    fclose(fd);
    return;
}

void free_stream(Tcp_List **head, Tcp_List *pre)
{
    Tcp_Node *pnode = NULL;
    pnode = (*head)->node_head.next;
    while (pnode != NULL) {
        Tcp_Node *pnext = pnode->next;
        Tcp_Node *anode = pnode->ack_node_head->next;
        while (anode != NULL) {
            Tcp_Node *next = anode->next;
            free(anode);
            anode = next;
        }
        free(pnode);
        pnode = pnext;
    }
    pre->next = (*head)->next;
    free(*head);
    return;
}

Tcp_Stream_Id get_stream_id(struct ip_header *ip_hdr, struct tcp_header *tcp_hdr)
{
    Tcp_Stream_Id id;
    char ip_src[50] = {0};
    char ip_dst[50] = {0};
    memset(&id, 0, sizeof(Tcp_Stream_Id));
    inet_ntop(AF_INET, &(ip_hdr->ip_src), ip_src);
    inet_ntop(AF_INET, &(ip_hdr->ip_dst), ip_dst);
    memcpy(id.ip_src, ip_src, 50);
    memcpy(id.ip_dst, ip_dst, 50);
    id.port_src = ntohs(tcp_hdr->tcp_src_port);
    id.port_dst = ntohs(tcp_hdr->tcp_dst_port);
    return id;
}

int is_same_stream(Tcp_Stream_Id *id1, Tcp_Stream_Id *id2, int *is_ack)
{
    if (id1->port_dst == id2->port_dst && id1->port_src == id2->port_src) {
        if (strcmp(id1->ip_src, id2->ip_src) == 0) {
            if (strcmp(id1->ip_dst, id2->ip_dst) == 0) {
                *is_ack = False;
                return True;
            }
        }
    }

    if (id1->port_src == id2->port_dst && id1->port_dst == id2->port_src) {
        if (strcmp(id1->ip_src, id2->ip_dst) == 0) {
            if (strcmp(id1->ip_dst, id2->ip_src) == 0) {
                *is_ack = True;
                return True;
            }
        }
    }

    return False;
}

void insert_node(unsigned long seq, int len, int syn, int fin, Tcp_Node *head, const u_char *packet)
{
    Tcp_Node *pnode = NULL;
    Tcp_Node *pre = head;
    for (pnode = head->next; pnode != NULL; pnode = pnode->next) {
        if (pnode->seq == seq) {
            if (pnode->len < len) {
                // copy the rest data to the node.
                memcpy(pnode->data + pnode->len, packet + pnode->len, len - pnode->len);
                pnode->len = len;
                pnode->fin = fin;
            }
            pnode->fin = fin;            
            break;
        } else if (pnode->seq < seq && pnode->seq + pnode->len > seq) {
            if (pnode->seq + pnode->len < seq + len) {
                // copy the rest data to the node.
                int overlap = pnode->seq + pnode->len - seq;
                memcpy(pnode->data + pnode->len, packet + overlap, len - overlap);
                pnode->len = overlap + pnode->len;
                pnode->fin = fin;
            }
            break;
        } else if (pnode->seq > seq) {
            if (seq + len <= pnode->seq) {
                // insert a node in middle.
                Tcp_Node *new_node = malloc(sizeof(Tcp_Node));
                memset(new_node, 0, sizeof(Tcp_Node));
                memcpy(new_node->data, packet, len);
                new_node->syn = syn;
                new_node->fin = fin;
                new_node->seq = seq;
                new_node->len = len;
                new_node->prev = pnode->prev;
                new_node->next = pnode;
                new_node->ack_node_head = malloc(sizeof(Tcp_Node));
                new_node->ack_len = len;
                memset(new_node->ack_node_head, 0, sizeof(Tcp_Node));
                pnode->prev->next = new_node;
                pnode->prev = new_node;
            } else {
                // reset the recv data.
                int overlap = seq + len - pnode->seq;
                unsigned char tmp[MAX_FRAME_LEN] = {0};
                memcpy(tmp, packet, overlap);
                memcpy(tmp + overlap, pnode->data, pnode->len);
                memcpy(pnode->data, tmp, sizeof(MAX_FRAME_LEN));
                pnode->seq = seq;
                pnode->len = overlap + pnode->len;
                pnode->fin = fin;
            }
            break;
        }
        pre = pnode;
    }
    if (pnode == NULL) {
        // insert a node at head or rear.
        Tcp_Node *new_node = malloc(sizeof(Tcp_Node));
        memset(new_node, 0, sizeof(Tcp_Node));
        memcpy(new_node->data, packet, len);
        new_node->syn = syn;
        new_node->fin = fin;
        new_node->seq = seq;
        new_node->len = len;
        new_node->prev = pre;
        new_node->next = NULL;
        new_node->ack_node_head = malloc(sizeof(Tcp_Node));
        memset(new_node->ack_node_head, 0, sizeof(Tcp_Node));
        new_node->ack_len = len;
        pre->next = new_node;
    }
    return;
}

void handle_tcp_stream(struct ip_header *ip_hdr, struct tcp_header *tcp_hdr, const u_char *packet, int length)
{
    Tcp_List *plist = NULL;
    Tcp_Stream_Id stream_id = get_stream_id(ip_hdr, tcp_hdr);
    int is_ack = False;
    Tcp_List *plist_pre = &tcp_list_head;
    for (plist = tcp_list_head.next; plist != NULL; plist = plist->next) {
        if (is_same_stream(&stream_id, &(plist->id), &is_ack) == True) {
            break;
        }
        plist_pre = plist;
    }
    
    unsigned long seq = ntohl(tcp_hdr->tcp_seq);
    unsigned long ack = ntohl(tcp_hdr->tcp_ack);
    int len = length;
    int syn = (tcp_hdr->th_flags & 0x02) >> 1;
    int fin = (tcp_hdr->th_flags & 0x01);
    if (plist == NULL) {
        if (syn == 1) {
            // first node in stream.
            plist = create_tcp_list(stream_id);
        } else {
            // discard this frame.
            return;
        }
    }
    
    Tcp_Node *pnode = NULL;
    if (is_ack == True) {
        for (pnode = plist->node_head.next; pnode != NULL; pnode = pnode->next) {
            if (pnode->seq + pnode->len == ack) {
                insert_node(seq, len, syn, fin, pnode->ack_node_head, packet);
                pnode->ack_len += len;
                break;
            }
        }
    } else {
        insert_node(seq, len, syn, fin, &(plist->node_head), packet);
        
        if (fin == 1) {
//            if (is_list_complete(&(plist->node_head)) == True) {
                write_list(&(plist->node_head));
//            }
            free_stream(&plist, plist_pre);
        }
    }
    return;
}

// Because we use pcap filter rule.
// So only get tcp packet here.
void get_frame_callback(u_char *args, const struct pcap_pkthdr *pcap_hdr, const u_char *packet)
{
    struct ip_header *ip_hdr = NULL;
    struct tcp_header *tcp_hdr = NULL;
    u_int8_t ip_hdr_len = 0x00;
    u_int8_t tcp_hdr_len = 0x00;

    // get ip header
    if (pcap_hdr->caplen < 14) {
        printf("ether frame's header < 14\n");
        return;
    }
    ip_hdr = (struct ip_header *) (packet + sizeof(struct ether_header));
    ip_hdr_len = ip_hdr->ip_vhl & 0x0f;
    if (ip_hdr_len < 5) {
        printf("ip frame's header len < 20 byte\n");
        return;
    }

    // get tcp header
    tcp_hdr = (struct tcp_header *) (packet + sizeof(struct ether_header) + ip_hdr_len * 4);
    tcp_hdr_len = (tcp_hdr->th_offx2 & 0xf0) >> 4;
    if (tcp_hdr_len < 5) {
        printf("tcp frame's header len < 20 byte\n");
        return;
    }
    int total_hdr_len = sizeof(struct ether_header) + (ip_hdr_len + tcp_hdr_len) * 4;
    handle_tcp_stream(ip_hdr, tcp_hdr, packet + total_hdr_len, pcap_hdr->caplen - total_hdr_len);
    return;
}

int main(int argc, char **argv)
{
    pcap_t *pdesc = NULL;
    char err_buff[PCAP_ERRBUF_SIZE] = {0};
    char *if_name = NULL;
    char pcap_filter_rule[MAX_STR_LEN] = {0};
    char mac_addr[MAX_STR_LEN] = {0};
    bpf_u_int32 bpf_mask = 0;
    struct bpf_program bpf_program = {0};

    memset(stream_id_arr, 0, sizeof(struct Stream_id));
    memset(&tcp_list_head, 0, sizeof(Tcp_List));
    
    // get network device name
    if_name = pcap_lookupdev(err_buff);
    if (if_name == NULL) {
        printf("Get net interface name error!\n");
        return 0;
    }

    // get mac address
    if (get_linux_mac_address(mac_addr, if_name) == -1) {
        printf("Get mac address error at device:%s:!\n", if_name);
        return 0;
    }

    // pcap open
    pdesc = pcap_open_live(if_name, 65536, 0, 30 * (10 ^ 3), err_buff);
    if (pdesc == NULL) {
        printf("pcap open error! ERROR MSG: %s\n", err_buff);
        return 0;
    }
    
    // set filter rule
    snprintf(pcap_filter_rule, MAX_STR_LEN, "tcp and (ether dst %s or ether src %s)", mac_addr, mac_addr);

    if (pcap_compile(pdesc, &bpf_program, pcap_filter_rule, 0, bpf_mask) == -1) {
        printf("pcap compile error!\n");
        return 0;
    }
    if (pcap_setfilter(pdesc, &bpf_program) == -1) {
        printf("pcap setfilter error!\n");
        return 0;
    }
    
    // set pcap loop
    if (pcap_loop(pdesc, -1, get_frame_callback, NULL) == -1) {
        printf("set pcap loop error!\n");
        return 0;
    }
    
    // pcap close
    pcap_close(pdesc);
    return 0;
}
