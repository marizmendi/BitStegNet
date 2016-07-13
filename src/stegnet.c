
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>            /* for NF_ACCEPT */

#include <libnetfilter_queue/libnetfilter_queue.h>

#define NF_IP_PRE_ROUTING   0
#define NF_IP_LOCAL_IN      1
#define NF_IP_FORWARD       2
#define NF_IP_LOCAL_OUT     3
#define NF_IP_POST_ROUTING  4
#define NF_IP_NUMHOOKS      5
#define ERR_INIT            -1

int ret = 0;
char * input;
int checksum_location = 22;
int offset = 48;
char * filename;

static uint32_t nfqueue_packet_get_id(struct nfq_data *packet)
{
        uint32_t id = -1;
        struct nfqnl_msg_packet_hdr *packetHeader;

        if ((packetHeader = nfq_get_msg_packet_hdr(packet)) != NULL)
                id = ntohl(packetHeader->packet_id);

        return id;
}

static uint32_t nfqueue_packet_get_hook(struct nfq_data *packet)
{

        uint32_t hook = -1;
        struct nfqnl_msg_packet_hdr *packetHeader;

        if ((packetHeader = nfq_get_msg_packet_hdr(packet)) != NULL)
                hook = packetHeader->hook;

        return hook;
}

static unsigned char* modify_pkt_data (struct nfq_data *tb)
{
        unsigned char *data;

        ret = nfq_get_payload(tb, &data);
        if (ret >= 0)
        {
                for (int i = offset; i < ret; ++i)
                {
                        data[i] = input[i - offset];
                }

                // set checksum = 0xFFFF
                data[checksum_location] = 255;
                data[checksum_location + 1] = 255;
        }

        return data;
}

static void show_pkt_data (struct nfq_data *tb)
{
        unsigned char *data;

        printf("Received message: ");

        ret = nfq_get_payload(tb, &data);
        if (ret >= 0)
        {
                for (int i = offset; i < ret; ++i)
                {
                        printf("%c", data[i]);
                }
        }
}

unsigned short checksum(void *b, int len)
{
        unsigned short *buf = b;
        unsigned int sum = 0;
        unsigned short result;

        for (sum = 0; len > 1; len -= 2)
                sum += *buf++;
        if (len == 1)
                sum += *(unsigned char*)buf;
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        result = ~sum;
        return result;
}

static unsigned char* fix_checksum (unsigned char * data)
{
        unsigned char a;
        unsigned char b;
        unsigned short chksm = checksum(data, 84);
        a = ((char *)(&chksm))[0];
        b = ((char *)(&chksm))[1];

        data[checksum_location] = a;
        data[checksum_location + 1] = b;
        return data;
}

void read_file()
{
        FILE *fp;
        long lSize;

        fp = fopen (filename, "rb");
        if (!fp) perror(filename), exit(1);

        fseek(fp, 0L, SEEK_END);
        lSize = ftell(fp);
        rewind(fp);

        /* allocate memory for entire content */
        // 4 is the maximum number of bytes.
        input = calloc(1, 48);
        if (!input) fclose(fp), fputs("memory alloc fails\n", stderr), exit(1);

        /* copy the file into the input */
        if (1 != fread(input, lSize, 1, fp))
                fclose(fp), free(input), fputs("entire read fails\n", stderr), exit(1);

        fclose(fp);
}

static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                    struct nfq_data *nfa, void *data)
{

        uint32_t hook = nfqueue_packet_get_hook(nfa);
        uint32_t id = nfqueue_packet_get_id(nfa);

        switch (hook) {

        case NF_IP_LOCAL_IN:
        {
                show_pkt_data(nfa);
                return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
        }

        case NF_IP_FORWARD:
        {
                puts("capturing packet from FORWARD iptables hook");
                return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
        }

        case NF_IP_LOCAL_OUT:
        {
                read_file();
                unsigned char *modified_data = modify_pkt_data(nfa);
                fix_checksum(modified_data);
                printf("Sending message from file %s\n", filename);
                return nfq_set_verdict(qh, id, NF_ACCEPT, ret, modified_data);
        }

        default:
                puts("error: capturing packet from an iptables hook we shouldn't");
                return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

        }
}

int main(int argc, char **argv)
{
        struct nfq_handle *h;
        struct nfq_q_handle *qh;
        struct nfnl_handle *nh;
        int fd;
        int rv;
        char buf[4096] __attribute__ ((aligned));
        int16_t queuenum = atoi(argv[1]);

        system("clear");


        if (queuenum == 0) {
                if (argc < 3) {
                        printf("%s\n", "Using default file message.txt");
                        filename = "message.txt";
                } else {
                        filename = argv[2];
                }
        }

        //printf("opening library handle\n");
        h = nfq_open();
        if (!h) {
                fprintf(stderr, "error during nfq_open()\n");
                exit(1);
        }

        //printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
        if (nfq_unbind_pf(h, AF_INET) < 0) {
                fprintf(stderr, "error during nfq_unbind_pf()\n");
                exit(1);
        }

        //printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
        if (nfq_bind_pf(h, AF_INET) < 0) {
                fprintf(stderr, "error during nfq_bind_pf()\n");
                exit(1);
        }

        //printf("binding this socket to queue '%i'\n", queuenum);
        if (queuenum == 0) {
                printf("Stegnet: transmitter mode\n");
        } else {
                printf("Stegnet: receiver mode\n");
        }
        qh = nfq_create_queue(h,  queuenum, &callback, NULL);
        if (!qh) {
                fprintf(stderr, "error during nfq_create_queue()\n");
                exit(1);
        }

        //printf("setting copy_packet mode\n");
        if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
                fprintf(stderr, "can't set packet_copy mode\n");
                exit(1);
        }

        fd = nfq_fd(h);

        while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
                printf("Torrent packet captured\n");
                nfq_handle_packet(h, buf, rv);
        }

        printf("unbinding from queue 0\n");
        nfq_destroy_queue(qh);

#ifdef INSANE
        /* normally, applications SHOULD NOT issue this command, since
         * it detaches other programs/sockets from AF_INET, too ! */
        printf("unbinding from AF_INET\n");
        nfq_unbind_pf(h, AF_INET);
#endif

        printf("closing library handle\n");
        nfq_close(h);

        exit(0);
}