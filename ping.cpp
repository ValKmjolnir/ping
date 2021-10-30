#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <vector>
#include <thread>
#include <ctime>

#include <unistd.h>
#include <sys/time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <wsipv6ok.h>
#include <ws2tcpip.h>
#else
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#pragma comment(lib,"ws2_32")

// g++ -std=c++11 -O3 ping.cpp -o ping.exe -lwsock32(windows)
// clang++ -std=c++11 -O3 ping.cpp -o ping -lpthread(linux)
int sd;
pid_t pid;
uint32_t counts=6;
uint32_t bytes=32;
sockaddr_in dst_addr;

struct ip{
	uint8_t ver;
	uint8_t tos; // type of service
	uint16_t len;// total length
	uint16_t id; // identification
	uint16_t off;// fragment offset field
	uint8_t ttl; // time to live
	uint8_t proto;
	uint16_t chksum;
	in_addr srcip;
	in_addr dstip;
};

struct icmp{
	uint8_t type;
	uint8_t code;
	uint16_t chksum;
	uint16_t id;
	uint16_t seq;
	uint32_t choose;
};

struct result{
	bool succ;
#ifdef _WIN32
	clock_t tm;
#else
	timeval tm;
#endif
}res[128];

#ifndef _WIN32
void tv_sub(timeval* out,timeval* in){
	if((out->tv_usec-=in->tv_usec)<0){
		--out->tv_sec;
		out->tv_usec+=1000000;
	}
	out->tv_sec-=in->tv_sec;
}
#endif

uint16_t chksum(uint16_t* buff,int size){
	uint32_t sum=0;
	while(size>1){
		sum+=*buff++;
		size-=sizeof(uint16_t);
	}
	if(size)
		sum+=*(unsigned char*)buff;
	sum=(sum>>16)+(sum&0xffff);
	sum+=(sum>>16);
	return (uint16_t)~sum;
}

void decode(char* buff,int size){
	ip* pkg=(ip*)buff;
	const int ipheadlen=(pkg->ver&0xf)<<2;
	if(size<ipheadlen+sizeof(icmp)){
		std::cout<<"ip header size error\n";
		return;
	}
	icmp* data=(icmp*)(buff+ipheadlen);
	uint16_t seq=0;
	if(data->type==0) // icmp echo reply
		seq=ntohs(data->seq);
	if(data->id!=pid){
		std::cout<<"id error\n";
		return;
	}
#ifdef _WIN32
	clock_t end=clock();
#else
	timeval end;
	gettimeofday(&end,nullptr);
	tv_sub(&end,&res[seq].tm);
#endif
	printf(
		"%d bytes time=%.2fms ttl=%d\n",
		size-20,
#ifdef _WIN32
		1000.0*(end-res[seq].tm)/(CLOCKS_PER_SEC*1.0),
#else
		(end.tv_sec*1000.0+end.tv_usec/1000.0),
#endif
		pkg->ttl);
}

void send_ping(){
	char data[1024];
	icmp* pkg=(icmp*)data;
	pkg->type=8; // icmp get echo request
	pkg->code=0;
	pkg->id=pid;
	for(uint32_t i=0;i<counts;++i){
		pkg->seq=htons(i);// host seq to net seq
		pkg->chksum=0;// set checksum to 0 first
		pkg->chksum=chksum((uint16_t*)data,bytes);
#ifdef _WIN32
		res[i].tm=clock();
#else
		gettimeofday(&res[i].tm,nullptr);
#endif
		if(sendto(sd,data,bytes,0,(sockaddr*)&dst_addr,sizeof(sockaddr))==-1){
			std::cout<<"failed to send\n";
			std::exit(-1);
		}
		sleep(1);
	}
}
void recv_ping(){
	sockaddr_in recv_addr;
	socklen_t recvlen=sizeof(recv_addr);
	char data[1024];
	for(uint32_t i=0;i<counts;++i){
		int len=recvfrom(sd,data,1024,0,(sockaddr*)&recv_addr,&recvlen);
		res[i].succ=(len!=-1);
		if(len!=-1){
			std::cout<<"reply from "<<inet_ntoa(recv_addr.sin_addr)<<": ";
			decode(data,len);
		}else{
			std::cout<<"timeout\n";
		}
	}
}
int main(int argc,const char* argv[]){
	std::vector<std::string> args;
	for(int i=0;i<argc;++i)
		args.push_back(argv[i]);
    if(argc<2 || (argc&1)){
        std::cout<<"usage: ping <host> -l <length> -n <counts>\n";
        std::exit(-1);
    }
	for(int i=2;i<argc;i+=2){
		if(args[i]=="-l")
			bytes=atoi(args[i+1].c_str());
		if(args[i]=="-n")
			counts=atoi(args[i+1].c_str());
	}
	bytes=bytes>512?512:bytes;
	counts=counts>128?128:counts;
#ifdef _WIN32 
    WSADATA wsaData; 
    if(WSAStartup(0x0101, &wsaData)){
		std::cout<<"failed to init winsock\n";
		std::exit(-1);
	}
#endif
    hostent* host;
    if((sd=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP))<0){
        std::cout<<"socket failed\n";
        std::exit(-1);
    }
    if((host=gethostbyname(argv[1]))==nullptr){
        std::cout<<"invalid argument\n";
        std::exit(-1);
    }
    memset(&dst_addr,0,sizeof(sockaddr_in));
	dst_addr.sin_family=AF_INET;
    memcpy(&dst_addr.sin_addr,host->h_addr,host->h_length);

	int ttl=64;
#ifdef _WIN32
	int timeout=2000;
#else
	timeval timeout={.tv_sec=2,.tv_usec=0};
#endif
	// set time to live, default 64
	setsockopt(sd,IPPROTO_ICMP,IP_TTL,(char*)&ttl,sizeof(ttl));
	setsockopt(sd,IPPROTO_ICMP,IP_MULTICAST_TTL,(char*)&ttl,sizeof(ttl));
	// set timeout
	setsockopt(sd,SOL_SOCKET,SO_RCVTIMEO,(char*)&timeout,sizeof(timeout));
	setsockopt(sd,SOL_SOCKET,SO_SNDTIMEO,(char*)&timeout,sizeof(timeout));
	std::cout
	<<"ping "<<argv[1]<<"["
	<<""<<inet_ntoa(dst_addr.sin_addr)<<"] "
	<<bytes<<" bytes "
	<<counts<<" packages\n";

    pid=getpid();

    std::thread thrd_send(send_ping);
    std::thread thrd_recv(recv_ping);
    thrd_send.join();
    thrd_recv.join();

	int succ_count=0;
	for(int i=0;i<counts;++i)
		if(res[i].succ)
			++succ_count;
	std::cout<<"send "<<counts<<" packages,received "<<succ_count<<" packages ("<<(counts-succ_count)*100.0/counts<<"% loss)\n";
#ifdef _WIN32	
    closesocket(sd);
    WSACleanup();
#else
	close(sd);
#endif
    return 0;
}