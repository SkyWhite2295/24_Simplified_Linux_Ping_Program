#include "ping.h"

struct proto	proto_v4 = { proc_v4, send_v4, NULL, NULL, 0, IPPROTO_ICMP };

#ifdef	IPV6
struct proto	proto_v6 = { proc_v6, send_v6, NULL, NULL, 0, IPPROTO_ICMPV6 };
#endif

int datalen = 56;		/* data that goes with ICMP echo request */

int set_broadcasting=0;//默认不使用广播
int set_ttl=0;//默认不修改跳数限制
int set_quiet=0;//默认不使用静默模式
int set_flood=0;//默认不使用极限检测
int set_debug=0;//默认不使用debug模式
int set_interval=0;//默认不修改时间间隔
int pingnum=4;//默认ping4次
int ttlnum=64;//默认跳数限制64
int intervaltime=1;//设置的默认发送间隔
unsigned char fill_byte=0;//默认填充字节
int set_adaptive = 0; // 是否启用自适应 ping
double adaptive_interval = 1.0; // 自适应间隔时间，初始为1秒
int set_audible = 0;//-a默认不发出提示音
int set_dont_route = 0;//-B默认允许ping改变包头的源地址
char *interface = NULL;//-I指定的本机接口
int timeout = 10000; // 默认超时时间为10000毫秒
int deadline = 0; // 默认deadline为0，表示不使用此功能
int preload = 0; // 默认不进行预加载
int set_no_dns = 0; // 默认为 0，表示默认解析主机名
//int record_route = 0;  // 默认为0，表示不记录路由
int no_routing = 0; // 默认为0，表示不启用直接路由模式
int mtu_strategy = 0; // 0: 'dont', 1: 'do', 2: 'want'
int packet_mark = 0; // 默认为0，表示没有设置标记
int full_user_latency = 0; // 默认为0，表示不启用完整的延迟统计
struct timeval start_time, end_time;

typedef struct {
    int option;  // 0: tsonly, 1: tsandaddr, 2: tsprespec
    char prespec_addrs[3][INET_ADDRSTRLEN];  // 存储预先指定的最多三个地址
    int num_addrs;  // 预设地址的数量
} timestamp_option_t;

timestamp_option_t ts_option = {0, {{0}}, 0};

int getpostcount=0;
double rttcount=0;
int rcvcount=0;

void printhelp(){
	printf("\n");
	printf("-h           显示帮助信息\n");
	printf("-b           允许ping一个广播地址，只用于IPv4\n");
	printf("-t ttl  设置TTL(Time To Live)为指定的值。该字段指定IP包被路由器丢弃之前允许通过的最大网段数\n");
	printf("-f           极限检测，快速连续ping一台主机\n");
	printf("-d           使用Socket的SO_DEBUG功能\n");

	printf("-q           不显示任何传送封包的信息，只显示最后的结果\n");
	printf("-s packetsize    指定每次ping发送的数据字节数，默认56，加上8字节的ICMP头，一共是64ICMP数据字节\n");
	printf("-v           使ping处于verbose方式，详细显示指令的执行过程\n");
	printf("-c count      ping指定次数后停止\n");
	printf("-i interval      设定间隔几秒发送一个ping包，默认一秒ping一次\n");
	printf("-p pattern  设置填满数据包的内容\n");
	printf("-A           自适应 ping，根据往返时间调整 ping 速度\n");
	printf("-a           接收到 ICMP 响应时播放声音\n");
	printf("-B           不允许ping改变包头的源地址\n");
	printf("-I interface	指定网卡接口、或指定的本机地址送出数据包\n");
	printf("-W timeout	以毫秒为单位设置ping的超时时间\n");
	printf("-w deadline	以秒为单位设置deadline\n");
	printf("-l preload	设置在送出要求信息之前，先行发出的数据包\n");
	printf("-n           不要将ip地址转换成主机名\n");
	//printf("-R           aaa\n");
	printf("-r           忽略正常的路由表，直接将数据包送到远端主机上，如果主机不直接连接的网络上，则错误。\n");
	printf("-T timestamp_option	设置IP timestamp选项,可以是下面的任何一个：‘tsonly’ (only timestamps) ‘tsandaddr’ (timestamps and addresses) ‘tsprespec host1 [host2 [host3]]’ (timestamp prespecified hops)\n");
	printf("-M hint		设置MTU（最大传输单元）分片策略。可设置为：‘do’：禁止分片，即使包被丢弃 ‘want’：当包过大时分片 ‘dont’：不设置分片标志（DF flag）\n");
	printf("-m mark		设置mark\n");
	printf("-U           打印从用户到用户的完整延迟\n");
}

int main(int argc, char **argv)
{
	int c;
	struct addrinfo	*ai;

	opterr = 0;		/* don't want getopt() writing to stderr */
	while ( (c = getopt(argc, argv, "hbt:fdqs:vc:i:pAaBI:W:w:l:nrT:M:m:U")) != -1) {//R
		switch (c) {
		case 'v':
			verbose++;
			break;
		case '?':
			err_quit("unrecognized option: %c", c);

		case 'h':
			printhelp();
			exit(0);
			break;
		case 'b':
			set_broadcasting=1;
			break;
		case 't':
			set_ttl=1;
			ttlnum = atoi(argv[optind-1]);
			break;
		case 'f':
			set_flood=1;
			break;
		case 'd':
			set_debug=1;
			break;

		case 'q':
			set_quiet=1;
			break;
		case 's':
			datalen=atoi(argv[optind-1]);
			if(datalen>1024||datalen<0)
				printf("数据包长度应大于0小于1024\n");
			break;
		case 'c':
			pingnum=atoi(argv[optind-1]);
			break;
		case 'i':
			set_interval=1;
			intervaltime=atoi(argv[optind-1]);
			if(intervaltime<=0) {
				fprintf(stderr, "错误：时间间隔应大于0\n");
				exit(EXIT_FAILURE); // 退出程序，返回非零值表示错误
			}
			break;
		case 'p':
			if (optind < argc) {
				fill_byte = (unsigned char)strtol(argv[optind], NULL, 10);
				optind++; // 确保在处理完参数后递增 optind
    			} else {
        			err_quit("-p 选项需要一个参数");
   			 }

			break;
            	case 'A': 
                	set_adaptive = 1;
                	break;	
                case 'a':
            		set_audible = 1;
            		break;	
            	case 'B':
		    	set_dont_route = 1; 
		    	break;
		case 'I':
		    	interface = optarg;
		    	break;
		case 'W':
			timeout = atoi(optarg);
			if (timeout <= 0) {
			    fprintf(stderr, "错误：超时时间必须大于0\n");
			    exit(EXIT_FAILURE);
			}
			break;
		case 'w':
			deadline = atoi(optarg);
			if (deadline < 0) {
			    fprintf(stderr, "错误：deadline 必须不小于0\n");
			    exit(EXIT_FAILURE);
			}
			break;
		case 'l':
			preload = atoi(optarg);
			if (preload < 0) {
			    fprintf(stderr, "错误：预加载的数据包数量必须大于或等于0\n");
			    exit(EXIT_FAILURE);
			}
			break;
		case 'n':
			set_no_dns = 1;
			break;
		//case 'R':
		//	record_route = 1;
		//	break;
		case 'r':
			no_routing = 1;
			break;
		case 'T':
			if (strcmp(optarg, "tsonly") == 0) {
			    ts_option.option = 0;
			} else if (strcmp(optarg, "tsandaddr") == 0) {
			    ts_option.option = 1;
			} else if (strncmp(optarg, "tsprespec", 9) == 0) {
			    ts_option.option = 2;
			    // Parse additional host addresses
			    char *token = strtok(optarg + 10, " ");
			    while (token != NULL && ts_option.num_addrs < 3) {
				strncpy(ts_option.prespec_addrs[ts_option.num_addrs++], token, INET_ADDRSTRLEN);
				token = strtok(NULL, " ");
			    }
			} else {
			    fprintf(stderr, "Invalid timestamp option\n");
			    exit(EXIT_FAILURE);
			}
			break;
		case 'M':
			if (strcmp(optarg, "do") == 0) {
			    mtu_strategy = 1;
			} else if (strcmp(optarg, "want") == 0) {
			    mtu_strategy = 2;
			} else if (strcmp(optarg, "dont") == 0) {
			    mtu_strategy = 0;
			} else {
			    fprintf(stderr, "Invalid MTU strategy option\n");
			    exit(EXIT_FAILURE);
			}
			break;
		case 'm':
			packet_mark = atoi(optarg);
			if (packet_mark < 0) {
			    fprintf(stderr, "Invalid mark value. Mark must be a non-negative integer.\n");
			    exit(EXIT_FAILURE);
			}
			break;
		case 'U':
			full_user_latency = 1;
			break;


		}
	}

	if (optind != argc-1)
		err_quit("usage: ping [ -v ] <hostname>");
	host = argv[optind];
	
	int length = strlen(host);
	int lastThreeChars = length - 3;
	char newString[lastThreeChars + 1];
	if (lastThreeChars > 0) {
        //printf("Last three characters of the host: %.*s", lastThreeChars, host + length - 3);
        strncpy(newString, host + length - 3, lastThreeChars);
         newString[lastThreeChars] = '\0';
    } else {
        //printf("The host name is shorter than 3 characters. No last three characters to display.");
    }
    int comparisonResult = strcmp(newString, "255");
    if (comparisonResult == 0 && set_broadcasting==0) {
        //printf("The last three characters of the host are '255'.");
        err_quit("若想要ping广播地址，请加入-b参数\n");
    } else {
        // printf("The last three characters of the host are not '255'.");
    }
    
	pid = getpid();
	signal(SIGALRM, sig_alrm);
	
	if (full_user_latency) {
        	gettimeofday(&start_time, NULL);
    	}


	ai = host_serv(host, NULL, 0, 0);
	
	if (full_user_latency) {
		gettimeofday(&end_time, NULL);
		printf("DNS resolution time: %.3f ms\n", (end_time.tv_sec - start_time.tv_sec) * 1000.0 + (end_time.tv_usec - start_time.tv_usec) / 1000.0);
	}
	

	printf("ping %s (%s): %d data bytes\n", ai->ai_canonname,
		   Sock_ntop_host(ai->ai_addr, ai->ai_addrlen), datalen);

		/* 4initialize according to protocol */
	if (ai->ai_family == AF_INET) {
		pr = &proto_v4;
#ifdef	IPV6
	} else if (ai->ai_family == AF_INET6) {
		pr = &proto_v6;
		if (IN6_IS_ADDR_V4MAPPED(&(((struct sockaddr_in6 *)
								 ai->ai_addr)->sin6_addr)))
			err_quit("cannot ping IPv4-mapped IPv6 address");
#endif
	} else
		err_quit("unknown address family %d", ai->ai_family);

	pr->sasend = ai->ai_addr;
	pr->sarecv = calloc(1, ai->ai_addrlen);
	pr->salen = ai->ai_addrlen;

	if (set_adaptive) {
	    struct itimerval timer;
	    timer.it_value.tv_sec = (int)adaptive_interval;
	    timer.it_value.tv_usec = (adaptive_interval - (int)adaptive_interval) * 1000000;
	    timer.it_interval.tv_sec = 0;
	    timer.it_interval.tv_usec = 0;
	    setitimer(ITIMER_REAL, &timer, NULL); // 设置初始定时器
	} else {
	    alarm(1); // 启动常规定时器
	}
	
	sockfd = socket(pr->sasend->sa_family, SOCK_RAW, pr->icmpproto);
	setuid(getuid());

	if (interface != NULL) {
		if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface)) < 0) {
	    		perror("setsockopt SO_BINDTODEVICE");
	    		exit(EXIT_FAILURE);
		}
	}

	if (set_dont_route) {
		int on = 1;
		if (setsockopt(sockfd, SOL_SOCKET, SO_DONTROUTE, &on, sizeof(on)) < 0) {
	    		perror("setsockopt SO_DONTROUTE");
	    		exit(EXIT_FAILURE);
		}
	}	

	readloop();

	exit(0);
}




void set_ip_direct_route(int sockfd, struct sockaddr *target) {
    if (no_routing && target->sa_family == AF_INET) {
        int on = 1;
        if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
            perror("setsockopt failed to set IP_HDRINCL");
            exit(EXIT_FAILURE);
        }
    }
}

void set_ip_timestamp(int sockfd) {
    unsigned char opt[40] = {0}; // 最大 IP 选项长度
    int optlen = 0;

    opt[0] = IPOPT_TIMESTAMP; // 时间戳选项类型
    opt[1] = sizeof(opt);     // 后面设置
    opt[2] = 5;               // 指针初始位置

    switch (ts_option.option) {
        case 0: // tsonly
            opt[3] = IPOPT_TS_TSONLY;
            break;
        case 1: // tsandaddr
            opt[3] = IPOPT_TS_TSANDADDR;
            break;
        case 2: // tsprespec
            opt[3] = IPOPT_TS_PRESPEC;
            for (int i = 0; i < ts_option.num_addrs; i++) {
                struct in_addr inaddr;
                inet_pton(AF_INET, ts_option.prespec_addrs[i], &inaddr);
                memcpy(opt + 4 + (i * 8), &inaddr, sizeof(inaddr));
            }
            break;
    }
    optlen = 4 + (ts_option.num_addrs * 8);
    opt[1] = optlen;

    if (setsockopt(sockfd, IPPROTO_IP, IP_OPTIONS, opt, optlen) < 0) {
        perror("setsockopt failed to set IP_OPTIONS");
        exit(EXIT_FAILURE);
    }
}

void set_ip_df(int sockfd) {
    if (pr->sasend->sa_family == AF_INET) {
        int val = IP_PMTUDISC_DO; // 默认 'do'
        if (mtu_strategy == 0) {
            val = IP_PMTUDISC_DONT; // 'dont'
        } else if (mtu_strategy == 2) {
            val = IP_PMTUDISC_WANT; // 'want'
        }
        if (setsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val)) < 0) {
            perror("setsockopt failed to set IP_MTU_DISCOVER");
            exit(EXIT_FAILURE);
        }
    } else if (pr->sasend->sa_family == AF_INET6) {
        int val = (mtu_strategy == 1) ? 1 : 0; // 仅在 'do' 情况下启用 DF
        if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_DONTFRAG, &val, sizeof(val)) < 0) {
            perror("setsockopt failed to set IPV6_DONTFRAG");
            exit(EXIT_FAILURE);
        }
    }
}

void set_socket_mark(int sockfd) {
    if (packet_mark != 0) { // 如果设置了标记
        if (setsockopt(sockfd, SOL_SOCKET, SO_MARK, &packet_mark, sizeof(packet_mark)) < 0) {
            perror("setsockopt failed to set SO_MARK");
            exit(EXIT_FAILURE);
        }
    }
}


void proc_v4(char *ptr, ssize_t len, struct timeval *tvrecv)
{
	int				hlen1, icmplen;
	double			rtt;
	struct ip		*ip;
	struct icmp		*icmp;
	struct timeval	*tvsend;

	ip = (struct ip *) ptr;		/* start of IP header */
	hlen1 = ip->ip_hl << 2;		/* length of IP header */

	icmp = (struct icmp *) (ptr + hlen1);	/* start of ICMP header */
	if ( (icmplen = len - hlen1) < 8)
		err_quit("icmplen (%d) < 8", icmplen);

	if (full_user_latency) {
		struct timeval now;
		gettimeofday(&now, NULL);
		double total_latency = (now.tv_sec - start_time.tv_sec) * 1000.0 + (now.tv_usec - start_time.tv_usec) / 1000.0;
		printf("Full user-to-user latency: %.3f ms\n", total_latency);
	}


	if (icmp->icmp_type == ICMP_ECHOREPLY) {
		if (icmp->icmp_id != pid)
			return;			/* not a response to our ECHO_REQUEST */
		if (icmplen < 16)
			err_quit("icmplen (%d) < 16", icmplen);

		tvsend = (struct timeval *) icmp->icmp_data;
		tv_sub(tvrecv, tvsend);
		rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;

		if(set_quiet!=1){
			//printf("%d bytes from %s: seq=%u, ttl=%d, rtt=%.3f ms\n",
			//	icmplen, Sock_ntop_host(pr->sarecv, pr->salen),
			//	icmp->icmp_seq, ip->ip_ttl, rtt);
			if (set_no_dns) {
                		printf("%d bytes from %s: seq=%u, ttl=%d, rtt=%.3f ms\n",
                    		icmplen, inet_ntoa(ip->ip_src),
                    		icmp->icmp_seq, ip->ip_ttl, rtt);
            		} else {
                		printf("%d bytes from %s: seq=%u, ttl=%d, rtt=%.3f ms\n",
                    		icmplen, Sock_ntop_host(pr->sarecv, pr->salen),
                    		icmp->icmp_seq, ip->ip_ttl, rtt);
            		}
			rttcount+=rtt;
			getpostcount++;
		}else{
			rttcount+=rtt;
			getpostcount++;
		}
		if (verbose) {
			printf("  %d bytes from %s: type = %d, code = %d\n",
				icmplen, Sock_ntop_host(pr->sarecv, pr->salen),
				icmp->icmp_type, icmp->icmp_code);
		}
		if (set_adaptive) {
            		adaptive_interval = rtt / 1000.0; // 根据 RTT 设置新的发送间隔
            		if (adaptive_interval < 0.1) adaptive_interval = 0.1; // 最小间隔时间为 0.1 秒
        	}
        	if (set_audible){
        	        printf("\a");
    			fflush(stdout);
        	}


    		
		rcvcount+=1;
	}
}

void proc_v6(char *ptr, ssize_t len, struct timeval* tvrecv)
{
#ifdef	IPV6
	int					hlen1, icmp6len;
	double				rtt;
	struct ip6_hdr		*ip6;
	struct icmp6_hdr	*icmp6;
	struct timeval		*tvsend;

	ip6 = (struct ip6_hdr *) ptr;		/* start of IPv6 header */
	hlen1 = sizeof(struct ip6_hdr);
	if (ip6->ip6_nxt != IPPROTO_ICMPV6)
		err_quit("next header not IPPROTO_ICMPV6");

	icmp6 = (struct icmp6_hdr *) (ptr + hlen1);
	if ( (icmp6len = len - hlen1) < 8)
		err_quit("icmp6len (%d) < 8", icmp6len);

	if (icmp6->icmp6_type == ICMP6_ECHO_REPLY) {
		if (icmp6->icmp6_id != pid)
			return;			/* not a response to our ECHO_REQUEST */
		if (icmp6len < 16)
			err_quit("icmp6len (%d) < 16", icmp6len);

		tvsend = (struct timeval *) (icmp6 + 1);
		tv_sub(tvrecv, tvsend);
		rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;

		//printf("%d bytes from %s: seq=%u, hlim=%d, rtt=%.3f ms\n",
		//		icmp6len, Sock_ntop_host(pr->sarecv, pr->salen),
		//		icmp6->icmp6_seq, ip6->ip6_hlim, rtt);
	        if (set_no_dns) {
		    	char addr[INET6_ADDRSTRLEN];
		    	inet_ntop(AF_INET6, &ip6->ip6_src, addr, sizeof(addr));
		   	printf("%d bytes from %s: seq=%u, hlim=%d, rtt=%.3f ms\n",
		        icmp6len, addr, icmp6->icmp6_seq, ip6->ip6_hlim, rtt);
		} else {
		    	printf("%d bytes from %s: seq=%u, hlim=%d, rtt=%.3f ms\n",
		        icmp6len, Sock_ntop_host(pr->sarecv, pr->salen),
		        icmp6->icmp6_seq, ip6->ip6_hlim, rtt);
		}	

	 	if (verbose) {
		printf("  %d bytes from %s: type = %d, code = %d\n",
				icmp6len, Sock_ntop_host(pr->sarecv, pr->salen),
				icmp6->icmp6_type, icmp6->icmp6_code);
		rcvcount+=1;
		}
		if (set_adaptive) {
            		adaptive_interval = rtt / 1000.0; // 根据 RTT 设置新的发送间隔
            		if (adaptive_interval < 0.1) adaptive_interval = 0.1; // 最小间隔时间为 0.1 秒
        	}
        	if (set_audible){
        	        printf("\a");
    			fflush(stdout);
        	}		
	}

#endif	/* IPV6 */
}

unsigned short in_cksum(unsigned short *addr, int len)
{
        int                             nleft = len;
        int                             sum = 0;
        unsigned short  *w = addr;
        unsigned short  answer = 0;

        /*
         * Our algorithm is simple, using a 32 bit accumulator (sum), we add
         * sequential 16 bit words to it, and at the end, fold back all the
         * carry bits from the top 16 bits into the lower 16 bits.
         */
        while (nleft > 1)  {
                sum += *w++;
                nleft -= 2;
        }

                /* 4mop up an odd byte, if necessary */
        if (nleft == 1) {
                *(unsigned char *)(&answer) = *(unsigned char *)w ;
                sum += answer;
        }

                /* 4add back carry outs from top 16 bits to low 16 bits */
        sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
        sum += (sum >> 16);                     /* add carry */
        answer = ~sum;                          /* truncate to 16 bits */
        return(answer);
}

void send_v4(void)
{
	set_ip_direct_route(sockfd, pr->sasend);
	if (ts_option.option != -1) { // 如果设置了时间戳选项
        	set_ip_timestamp(sockfd);
    	}
	set_ip_df(sockfd);
	set_socket_mark(sockfd);

	int			len;
	struct icmp	*icmp;
	
	icmp = (struct icmp *) sendbuf;
	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_code = 0;
	icmp->icmp_id = pid;
	icmp->icmp_seq = nsent++;
	gettimeofday((struct timeval *) icmp->icmp_data, NULL);

	//使用fill_byte 填充数据部分
	memset(icmp + 1,fill_byte,datalen); // icmp + 1 跳过 ICMP 头部

	len = 8 + datalen;		/* checksum ICMP header and data */
	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = in_cksum((u_short *) icmp, len);

	sendto(sockfd, sendbuf, len, 0, pr->sasend, pr->salen);
}

void send_v6()
{
#ifdef	IPV6
	int					len;
	struct icmp6_hdr	*icmp6;

	set_ip_df(sockfd);
	set_socket_mark(sockfd);
	
	icmp6 = (struct icmp6_hdr *) sendbuf;
	icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
	icmp6->icmp6_code = 0;
	icmp6->icmp6_id = pid;
	icmp6->icmp6_seq = nsent++;
	gettimeofday((struct timeval *) (icmp6 + 1), NULL);


	len = 8 + datalen;		/* 8-byte ICMPv6 header */

	sendto(sockfd, sendbuf, len, 0, pr->sasend, pr->salen);
		/* 4kernel calculates and stores checksum for us */
#endif	/* IPV6 */
}

void readloop(void)
{
	int				size;
	char			recvbuf[BUFSIZE];
	socklen_t		len;
	ssize_t			n;
	struct timeval	tval;

	sockfd = socket(pr->sasend->sa_family, SOCK_RAW, pr->icmpproto);
	setuid(getuid());		/* don't need special permissions any more */

// 创建一个用于检测的 UDP 套接字
	int probe_fd = socket(AF_INET, SOCK_DGRAM, 0);

	if(set_broadcasting==1){
		setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST,&set_broadcasting, sizeof(set_broadcasting));
//		if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST,&set_broadcasting, sizeof(set_broadcasting)) < 0) {
//			perror ("can't set set_broadcasting");}
//			exit(2);
	}
	if (set_ttl==1) {
		int ittl = ttlnum;
		if (setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_TTL,&ttlnum, 1) == -1) {//多播的ttl
			perror ("ping: can't set multicast time-to-live");
			exit(2);
		}
		if (setsockopt(sockfd, IPPROTO_IP, IP_TTL,&ittl, sizeof(ittl)) == -1) {//单播的ttl
			perror ("ping: can't set unicast time-to-live");
			exit(2);
		}
	}
	if (set_debug){
		setsockopt(sockfd, SOL_SOCKET, SO_DEBUG, &set_debug, sizeof(set_debug));
	}
	
	struct timeval tv_timeout;
	tv_timeout.tv_sec = timeout / 1000;
	tv_timeout.tv_usec = (timeout % 1000) * 1000;

	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv_timeout, sizeof(tv_timeout));

	time_t start_time = time(NULL);


	size = 60 * 1024;		/* OK if setsockopt fails */
	setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));

	sig_alrm(SIGALRM);		/* send first packet */
	
	    // 发送预加载的数据包s
	for (int i = 0; i < preload; i++) {
		(*pr->fsend)();
	}

	
	int i=0;

	for ( ; ; ) {
		if (deadline > 0 && (time(NULL) - start_time > deadline)) {
		    printf("达到设定的deadline，终止ping操作。\n");
		    break;
		}
	
		if(rcvcount>=pingnum){
			break;
		}
		len = pr->salen;
		
		n = recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0, pr->sarecv, &len);
		if (n < 0) {
			if (errno == EINTR){
				continue;
			}
			if (errno == EWOULDBLOCK) {
				printf("接收超时。\n");
				break;
			}

			else
				err_sys("recvfrom error");
		}

		gettimeofday(&tval, NULL);
		(*pr->fproc)(recvbuf, n, &tval);

	}
	printf("一共发送%d数据包  接收到%d  总rtt=%.3f ms 平均rtt=%.3f ms\n",pingnum,getpostcount,rttcount,rttcount/getpostcount);

}

void sig_alrm(int signo)
{
        (*pr->fsend)();
		if(set_flood){
			ualarm(100,1);// 100/s
		}
		else if (set_adaptive) {
        		struct itimerval timer;
        		timer.it_value.tv_sec = (int)adaptive_interval;
        		timer.it_value.tv_usec = (adaptive_interval - (int)adaptive_interval) * 1000000;
        		timer.it_interval.tv_sec = 0;
        		timer.it_interval.tv_usec = 0;
        		setitimer(ITIMER_REAL, &timer, NULL); // 设置自适应定时器
    		}
		else if(set_interval){
			alarm(intervaltime);
		}
		else{
			alarm(1);//1s
		}
        return;         /* probably interrupts recvfrom() */
}

void tv_sub(struct timeval *out, struct timeval *in)
{
	if ( (out->tv_usec -= in->tv_usec) < 0) {	/* out -= in */
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}




char *
sock_ntop_host(const struct sockaddr *sa, socklen_t salen)
{
    static char str[128];               /* Unix domain is largest */

        switch (sa->sa_family) {
        case AF_INET: {
                struct sockaddr_in      *sin = (struct sockaddr_in *) sa;

                if (inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str)) == NULL)
                        return(NULL);
                return(str);
        }

#ifdef  IPV6
        case AF_INET6: {
                struct sockaddr_in6     *sin6 = (struct sockaddr_in6 *) sa;

                if (inet_ntop(AF_INET6, &sin6->sin6_addr, str, sizeof(str)) == NULL)
                        return(NULL);
                return(str);
        }
#endif

#ifdef  HAVE_SOCKADDR_DL_STRUCT
        case AF_LINK: {
                struct sockaddr_dl      *sdl = (struct sockaddr_dl *) sa;

                if (sdl->sdl_nlen > 0)
                        snprintf(str, sizeof(str), "%*s",
                                         sdl->sdl_nlen, &sdl->sdl_data[0]);
                else
                        snprintf(str, sizeof(str), "AF_LINK, index=%d", sdl->sdl_index);
                return(str);
        }
#endif
        default:
                snprintf(str, sizeof(str), "sock_ntop_host: unknown AF_xxx: %d, len %d",
                                 sa->sa_family, salen);
                return(str);
        }
    return (NULL);
}

char * Sock_ntop_host(const struct sockaddr *sa, socklen_t salen)
{
        char    *ptr;

        if ( (ptr = sock_ntop_host(sa, salen)) == NULL)
                err_sys("sock_ntop_host error");        /* inet_ntop() sets errno */
        return(ptr);
}

struct addrinfo * host_serv(const char *host, const char *serv, int family, int socktype)
{
        int                             n;
        struct addrinfo hints, *res;

        bzero(&hints, sizeof(struct addrinfo));
        hints.ai_flags = AI_CANONNAME;  /* always return canonical name */
        hints.ai_family = family;               /* AF_UNSPEC, AF_INET, AF_INET6, etc. */
        hints.ai_socktype = socktype;   /* 0, SOCK_STREAM, SOCK_DGRAM, etc. */

        if ( (n = getaddrinfo(host, serv, &hints, &res)) != 0)
                return(NULL);

        return(res);    /* return pointer to first on linked list */
}
/* end host_serv */

static void err_doit(int errnoflag, int level, const char *fmt, va_list ap)
{
        int             errno_save, n;
        char    buf[MAXLINE];

        errno_save = errno;             /* value caller might want printed */
#ifdef  HAVE_VSNPRINTF
        vsnprintf(buf, sizeof(buf), fmt, ap);   /* this is safe */
#else
        vsprintf(buf, fmt, ap);                                 /* this is not safe */
#endif
        n = strlen(buf);
        if (errnoflag)
                snprintf(buf+n, sizeof(buf)-n, ": %s", strerror(errno_save));
        strcat(buf, "\n");

        if (daemon_proc) {
            //    syslog(level, buf);
        } else {
                fflush(stdout);         /* in case stdout and stderr are the same */
                fputs(buf, stderr);
                fflush(stderr);
        }
        return;
}


/* Fatal error unrelated to a system call.
 * Print a message and terminate. */

void err_quit(const char *fmt, ...)
{
        va_list         ap;

        va_start(ap, fmt);
        err_doit(0, LOG_ERR, fmt, ap);
        va_end(ap);
        exit(1);
}

/* Fatal error related to a system call.
 * Print a message and terminate. */

void err_sys(const char *fmt, ...)
{
        va_list         ap;

        va_start(ap, fmt);
        err_doit(1, LOG_ERR, fmt, ap);
        va_end(ap);
        exit(1);
}


/*
 * getopt是由Unix标准库提供的函数，查看命令man 3 getopt。
 * 
 * getopt函数的参数：
 * 参数argc和argv：通常是从main的参数直接传递而来，argc是参数的数量，
 *                 argv是一个常量字符串数组的地址。
 * 参数optstring：一个包含正确选项字符的字符串，如果一个字符后面有冒号，
                  那么这个选项在传递参数时就需要跟着一个参数。

 * 外部变量：
 * char *optarg：如果有参数，则包含当前选项参数字符串
 * int optind：argv的当前索引值。当getopt函数在while循环中使用时，
 *             剩下的字符串为操作数，下标从optind到argc-1。            
 * int opterr：这个变量非零时，getopt()函数为“无效选项”和“缺少参数选项，
 *             并输出其错误信息。
 * int optopt：当发现无效选项字符之时，getopt()函数或返回 \’ ? \’ 字符，
 *             或返回字符 \’ : \’ ，并且optopt包含了所发现的无效选项字符。
 */
