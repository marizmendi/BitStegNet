
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>            /* for NF_ACCEPT */

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <math.h>

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
int packet_type;
int pkt_ctr = 0;
int startp = -1;
char buff[1];
int first = 1;
int fin = 0;

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

unsigned char getbit(unsigned char *bits, unsigned long n) {
        return (bits[n / 8] & (unsigned char)pow(2, n % 8)) >> n % 8;
}

void setbit(unsigned char *bits, unsigned long n, unsigned char val) {
        bits[n / 8] =
                (bits[n / 8] & ~(unsigned char)pow(2, n % 8)) | ((unsigned char)
                                pow(2,
                                    n % 8) * val);
}

const char *byte_to_binary(int x)
{
        static char b[9];
        b[0] = '\0';

        int z;
        for (z=128; z>0; z>>=1)
        {
                strcat(b,((x&z)==z)?"1":"0");
        }

        return b;
}

static void set_pkt_type (struct nfq_data *tb)
{

        unsigned char *data;

        ret = nfq_get_payload(tb, &data);
        if (ret >= 0)
        {
                packet_type = data[28];
        }
}

static void show_pkt_type (struct nfq_data *tb)
{
        unsigned char *data;

        printf("Packet Type: ");

        ret = nfq_get_payload(tb, &data);
        if (ret >= 0)
        {
                switch (packet_type) {

                case 1:
                {
                        printf("DATA\n");
                        return;
                }

                case 17:
                {
                        printf("FIN\n");
                        return;
                }

                case 33:
                {
                        printf("STATE\n");
                        return;
                }

                case 65:
                {
                        printf("SYN\n");
                        return;
                }

                }
        }
}

static void show_pkt_data (struct nfq_data *tb)
{
        unsigned char *data;

        printf("Received package \n");

        ret = nfq_get_payload(tb, &data);
        if (ret >= 0)
        {
                for (int i = 0; i < ret; ++i)
                {
                        printf("data[%u] : ", i);
                        printf("%x ", data[i]);
                        printf("%s\n", byte_to_binary(data[i]));

                }
                printf("\n");
        }
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

unsigned int is_lsb_set(unsigned value)
{
        return (value & (1 << 0)) != 0;
}

static void show_utp_timestamp_data (struct nfq_data *tb)
{
        unsigned char *data;

        ret = nfq_get_payload(tb, &data);
        if (ret >= 0)
        {

                printf("data[35] : %u\ndata[39] : %u\n", is_lsb_set(data[35]),is_lsb_set(data[39]));

                for (int i = 32; i < 40; ++i)
                {
                        printf("data[%u] : ", i);
                        printf("%x : ", data[i]);
                        printf("%s\n", byte_to_binary(data[i]));
                }
                printf("\n");
        }
}

static void show_utp_timestamp_lsb (struct nfq_data *tb)
{
        unsigned char *data;

        ret = nfq_get_payload(tb, &data);
        if (ret >= 0)
        {

                if((pkt_ctr-1)%8==0){
                        printf("\nBYTE:");
                }

                printf("%s", is_lsb_set(data[35])?"1":"0");
        }
}

static unsigned char get_utp_timestamp_lsb (struct nfq_data *tb)
{
        unsigned char *data;

        ret = nfq_get_payload(tb, &data);
        if (ret >= 0)
        {
                return is_lsb_set(data[35])?1:0;
        }
}

static unsigned char* modify_utp_timestamp_data (struct nfq_data *tb, unsigned char bit)
{
        unsigned char *data;

        ret = nfq_get_payload(tb, &data);
        if (ret >= 0)
        {
                // if((pkt_ctr-1)%8==0){
                //         printf("\nBYTE:");
                // }

                //rand()%2==1
                if(bit==1)
                {
                        if(!is_lsb_set(data[35]))
                        {
                                data[39]--;    
                        }

                        data[35] |= 1;
                }
                else
                {
                        if(is_lsb_set(data[35]))
                        {
                                data[39]++;
                        }

                        data[35] &= ~1;
                }
                //printf("\n");
        }

        return data;
}

// void read_file()
// {
//         FILE *fp;
//         long lSize;

//         fp = fopen (filename, "rb");
//         if (!fp) perror(filename), exit(1);

//         fseek(fp, 0L, SEEK_END);
//         lSize = ftell(fp);
//         rewind(fp);

//         /* allocate memory for entire content */
//         // 4 is the maximum number of bytes.
//         input = calloc(1, 48);
//         if (!input) fclose(fp), fputs("memory alloc fails\n", stderr), exit(1);

//         /* copy the file into the input */
//         if (1 != fread(input, lSize, 1, fp))
//                 fclose(fp), free(input), fputs("entire read fails\n", stderr), exit(1);

//         fclose(fp);
// }


static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                    struct nfq_data *nfa, void *data)
{

        uint32_t hook = nfqueue_packet_get_hook(nfa);
        uint32_t id = nfqueue_packet_get_id(nfa);

        set_pkt_type(nfa);
        
        if(fin)
            exit(0);

        switch (hook) {

        case NF_IP_LOCAL_IN:
        {
                // printf("Packet counter: %u\n", pkt_ctr);
                // show_pkt_type(nfa);    

                //packet_type==1
                if(packet_type==1){

                        pkt_ctr++;

                        if (first) {
                                printf("Reciever...\n");
                                first = 0;
                                startp = 0;
                        } else {
                                if (startp == 0)
                                        printf("BYTE: \n");

                                unsigned char bit = get_utp_timestamp_lsb(nfa);

                                printf("%i", bit);
                                setbit(buff, startp, bit);

                                fflush(stdout);
                                startp++;

                                if (startp % 8 == 0) {
                                        int c = buff[0];
                                        printf(" (%c) \n", c);
                                        if(c == 10)
                                        {
                                            exit(0);
                                        }
                                        startp = 0;
                                }
                        }

                }
                return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
        }

        case NF_IP_FORWARD:
        {
                puts("capturing packet from FORWARD iptables hook");
                return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
        }

        case NF_IP_LOCAL_OUT:
        {

                // printf("Packet counter: %u\n", pkt_ctr);
                // show_pkt_type(nfa);    

                //packet_type==1
                if(packet_type==1){
                        pkt_ctr++;

                        //read_file();
                        //show_pkt_data(nfa);
                        //show_utp_timestamp_data(nfa);

                        if (startp == -1) {
                                printf("Transmitter...\n");

                                int b = fgetc(stdin);
                                if (b == EOF)
                                {
                                        b = 0;   
                                        exit(0);                                     
                                }

                                buff[0] = b;
                                startp = 0;
                                return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
                        }

                        unsigned char bit = getbit(buff, startp);

                        if (startp == 0) {
                                printf("BYTE: \n");
                        }

                        printf("%i", bit);
                        unsigned char *modified_data = modify_utp_timestamp_data(nfa, bit);

                        fflush(stdout);

                        startp++;

                        if (startp % 8 == 0) {
                                printf(" (%c)\n", buff[0]);

                                int b = fgetc(stdin);
                                if (b == EOF)
                                {
                                        b = 0;
                                        fin=1;
                                }

                                buff[0] = b;
                                startp = 0;
                        }

                        return nfq_set_verdict(qh, id, NF_ACCEPT, ret, modified_data);


                } else {
                        //show_utp_timestamp_data(nfa);
                        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
                }



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
        int16_t queuenum ;
        // TODO Check if not argv[1]
        if(argc > 1){
                queuenum = atoi(argv[1]);
        } else {
                printf("%s\n", "Missing queue number");
                exit(1);
        }

        system("clear");


        // if (queuenum == 0) {
        //         if (argc < 3) {
        //                 printf("%s\n", "Using default file message.txt");
        //                 filename = "message.txt";
        //         } else {
        //                 filename = argv[2];
        //         }
        // } else {
        //     if (argc < 2) {
        //         printf("%s\n", "Needed arguments");
        //         exit(1);
        //     }
        // }

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
                printf("BitStegnet: transmitter mode\n");
        } else {
                printf("BitStegnet: receiver mode\n");
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
                //printf("\n\nTorrent packet captured\n");
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