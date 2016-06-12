#ifndef __TRANSMIT_MAIN_H__
#define __TRANSMIT_MAIN_H__

#define __WIN32__ 1

#ifdef __WIN32__

#pragma pack(1)
#define inline __inline
#define MSG_DONTWAIT 0



#endif


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __WIN32__
//#include <winsock.h>
#define  snprintf _snprintf
#include <winsock2.h>
#include <windows.h>
#include <errno.h>
#include <pthread.h>
#include <winbase.h>
#include <shlwapi.h>
#include <stdlib.h>
#else
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>


#include <unistd.h> 
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <locale.h>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <errno.h>
#include <pthread.h>
#include <assert.h>

#endif


//#include <linux/delay.h>


//#include <my_global.h>  //my sql
//#include "mysql.h"
//#include "libavformat/avformat.h"
//#include "mp4v2/mp4v2.h"

#pragma comment(lib, "pthreadVC2.lib")

#define USE_H264BSF 1

#define RTP_PACK_PT_LEN (1460) //1350


#define __DEBUG__  
#ifdef __DEBUG__  
#define DEBUG(format,...) printf("File: "__FILE__", Line: %d: "format, __LINE__, ##__VA_ARGS__)  //' ## '的意思是，如果可变参数被忽略或为空，将使预处理器（ preprocessor ）去除掉它前面的那个逗号。）
#else  
#define DEBUG(format,...)  
#endif 


typedef unsigned long long int uint64_t;
typedef unsigned int uint32_t;


#define MAX_CONNECT_COUNT 200  //thread pool 

#define UDP_TRANSMIT 0
#define TCP_TRANSMIT 1

#define AUTH_BASE64 0
#define AUTH_MD5 1


#define RTP_BASE_PORT  5300

#define RTSP_PORT  5300  //554

#define MEDIA_STREAM_VIDEO 1
#define MEDIA_STREAM_AUDIO 2


//file : D:/HDA/Red5/webapps/vod/streams/032828/20150529165441/PIC0001.JPG  032828警员编号

#define MEDIA_FILE_PATH_PREFIX  "D:\\vc_test_ma\\rtsp_win\\rtsp\\rtsp\\"       //"/opt_marvell/rtsp/"

#define RECV_BUF_MAX_LEN (10*1024)  
#define SEND_BUF_MAX_LEN (10*1024) 
#define SEND_STREAM_MAX_LEN (3*1024*1024)
#define SEND_STREAM_AUDIO_MAX_LEN (1024*1024)


#define ERR_APP_REG_OK 0
#define ERR_APP_REG_HAVE 1  // 已经注册了
#define ERR_APP_REG_NO_RES 2  //没有资源了
#define ERR_APP_REG_USER 3  //用户 密码 错误
#define ERR_APP_REG_STATUE 4  //注册查表错误
#define ERR_APP_REG_NO 5  // 没有注册了
#define ERR_APP_STREAM_HAVE 6  // 码流已经在上传
#define ERR_APP_PROCESSING 7  // 请求正在处理，对方稍后再次重复请求

#define VOD_DN_FILE  1
#define VOD_DN_STREAM 2
#define VOD_UP_FILE 3
#define VOD_UP_STREAM 4

#define CMD_UP_STREAM 40

#define RTSP_ERR_DISCONNECT (-100)
#define RTSP_ERR_OK (0)
#define RTSP_ERR_FAIL (-1)
#define RTSP_ERR_END (-99)  // TEARDOWN request

#define DIV_FILE_MAX_COUNT 1000 //save on dev memory



#define SESSION_STATUE_DEFAULT 0
#define SESSION_STATUE_OPTIONS 1
#define SESSION_STATUE_DESCRIBE 2  //describe
#define SESSION_STATUE_SETUP_VIDEO 3  //setup
#define SESSION_STATUE_SETUP_AUDIO 4  //setup
#define SESSION_STATUE_PLAY 5  //play
#define SESSION_STATUE_SEND_STREAM 6  //send rtcp
#define SESSION_STATUE_END_STREAM 7   //send stream end
#define SESSION_STATUE_PAUSE 8
#define SESSION_STATUE_TEARDOWN 9

#define CODEC_H264 1
#define CODEC_H265 2
#define CODEC_AAC 1
#define CODEC_G711U 2

extern FILE *fp_gvideo; 
extern int rd_fd;
extern int wr_fd;

typedef struct _CLIENT_THREAD_INFO CLIENT_THREAD_INFO;

struct _CLIENT_THREAD_INFO
{
 char thread_status; //0->default  1->create  2-> alloc to client  3->work ok  4->thread exit
 int sockfd;
 char sockfd_statue; //0->default 1->connect 2->disconnect 
 char remote_ip[64]; 
 int remote_port; 
 char local_ip[64];
 int index;
 unsigned char *recv_buf;
 int recv_buf_max_len;
 int recv_buf_left_len;
 unsigned char *send_buf;
 int send_buf_max_len;
 int send_buf_left_len; //send rtsp cmd
 char cur_free; //0->free  1->busy
 char send_respon_flag;

};


extern CLIENT_THREAD_INFO  bridge_thread_pool[MAX_CONNECT_COUNT];
#define MAX_REQ_RTSP_CMD_COUNT 20





typedef struct _SEED_DATA
{
 struct timeval timestamp;
 unsigned int counter;
}SEED_DATA;

extern int delay_ms(double msec);
extern void *thread_rtsp(void *p);
extern void thread_sleep(int u_val);
extern void WidebrightSegvHandler(int signum);
extern int set_socket_attr(int *skt, int timeout);
extern int create_socket(char skt_type,int skt_port);
extern int rtsp_check_req_end(char *in,int in_len);
extern int dateHeader(char *in,int in_len);
extern int rtsp_get_key_val(char *key_str,char *in,int in_len,char *out,int out_len);
extern char *md5_compute(const unsigned char *data, unsigned int len, char *buf);
extern int rtsp_set_nonce(char *out,int out_len);
extern int base64_decode(unsigned char *out, const char *in, int in_size, int out_size);
extern int rtsp_get_host_info(char *out,int out_len);

extern int rtsp_sock_recv(CLIENT_THREAD_INFO *thread_info);
extern int rtsp_sock_send(CLIENT_THREAD_INFO *thread_info);
extern int rtsp_dateHeader(char *out,int out_len);
extern int move_str_space_left_right(char *in,int in_len);
extern int rtsp_get_key_val_int(char *key_str,char *in,int in_len,char *out,int out_len);
extern int  rtsp_session(char *out,int out_len);
extern int rtsp_verify_user(char *in,int in_len,char auth_type);
extern long our_random();
extern int rtsp_check_filename(char *in,int in_len,char *out,int out_len);
extern int rtp_file(CLIENT_THREAD_INFO *thread_info);

#endif




