
#if 1 //def __WIN32__
#ifdef __cplusplus 
extern "C"{ 
#endif
#include "rtsp_main.h"
#ifdef __cplusplus 
} 
#endif

#else
#include "rtsp_main.h"
#endif


#pragma comment(lib, "ws2_32.lib")

static const int mpeg4audio_sample_rates[16] = {
96000, 88200, 64000, 48000, 44100, 32000,
24000, 22050, 16000, 12000, 11025, 8000, 7350
};



static unsigned nonce_counter = 0;

#define AV_BASE64_SIZE(x)  (((x)+2) / 3 * 4 + 1)


static char ch_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
//-------------------------------------------------------------------------------
static unsigned int base64_2_index(char base64_ch)
{
    unsigned int ch_index = 0;

    if(base64_ch >= 'A' && base64_ch <= 'Z')   //A index 0
    {
        ch_index = base64_ch - 'A';
    }
    else if(base64_ch >= 'a' && base64_ch <= 'z')  //a index 26
    {
        ch_index = base64_ch - 71;
    }
    else if(base64_ch >= '0' && base64_ch <= '9')  //0 index 52
    {
        ch_index = base64_ch + 4;
    }

    else if(base64_ch == '+') //0 index 62
    {
        ch_index = 62;
    }
    else if(base64_ch == '/') //0 index 63
    {
        ch_index = 63;
    }
    else if(base64_ch == '=') //0 index 63
    {
        ch_index = 0;
    }

    return ch_index;

}

//-------------------------------------------------------------------------
int base64_decode(unsigned char *out, const char *in, int in_size, int out_size)
{

    unsigned int tmp_val = 0;
    unsigned int tmp_ch = 0;
    unsigned int ch_0 = 0;
    unsigned int ch_1 = 0;
    unsigned int ch_2 = 0;
    unsigned int ch_3 = 0;

    unsigned int pad_count = 0;

    int i = 0;
    int k = 0;

    if((in_size % 4) != 0)
    {
        printf("base64_decode base64 str error,in_size:%d,val:%s\n", in_size, in);
        return -1;
    }

    //   printf("base64_decode_ma will decode str:%s\n",in);

    memset(out, 0, out_size);

    tmp_val = 0;
    tmp_ch = 0;


    for(i = 0; i < in_size; i++)
    {
        if(*(in + i) == '=')
        {
            pad_count = pad_count + 1;
        }
    }


    i = 0;
    k = 0;
    while(i < in_size)
    {




        //ch_0 is index val

        ch_0 = base64_2_index(*(in + i + 0));
        ch_1 = base64_2_index(*(in + i + 1));
        ch_2 = base64_2_index(*(in + i + 2));
        ch_3 = base64_2_index(*(in + i + 3));






        ch_0 = ch_0 << 24;
        ch_1 = ch_1 << 16;
        ch_2 = ch_2 << 8;
        ch_3 = ch_3 << 0;


        ch_0 = ch_0 << 2;
        ch_1 = ch_1 << 2;
        ch_2 = ch_2 << 2;
        ch_3 = ch_3 << 2;


        tmp_ch = ch_0  + (ch_1 << 2) + (ch_2 << 4) + (ch_3 << 6);
        //   printf("tmp_ch val:0x%08x\n",tmp_ch);

        out[k + 0] = (tmp_ch >> 24);
        out[k + 1] = (tmp_ch >> 16);
        out[k + 2] = (tmp_ch >> 8);

        i = i + 4;
        k = k + 3;



    }

    // printf(">>>>>>base64_decode alway decode str len:%d,%d\n",k,pad_count);

    //  printf("base64_decode alway decode str:%s,len:%d\n",out,(k-pad_count));

    return (k - pad_count);



}

//-------------------------------------------------------------------------
static char *base64(unsigned char *in, int in_len, char *key)
{

    int buf_len = in_len;
    // char *buf="admin:admin";

    // char base_str[200]={0};

    char *buf = in;
    char *base_str = key;

    long tmp_val = 0;

    int src_proc_len = 0;
    int det_proc_len = 0;

    int i = 0,n=0,m=0;
    unsigned char ch=0;
    unsigned char ch_0=0,ch_1=0,ch_2=0;


    if(in==0 || in_len<=0 || key==0)
        return 0;

   // for(i=0;i<user_buf_len;i++)
   // {
   //  DEBUG("base64 i=%d val=0x%02x\n",i,user_buf[i]);
   // }
   

    n=buf_len/3;
    m=buf_len%3;
   // DEBUG("base64 n=%d m=%d\n",n,m);
    
    for(i = 0; i < n; i++)
    {

          ch_0 = *(buf + src_proc_len + 0);
          ch_1 = *(buf + src_proc_len + 1);
          ch_2 = *(buf + src_proc_len + 2);

       tmp_val = ch_0;
       tmp_val=(tmp_val<<8)+ch_1;
       tmp_val=(tmp_val<<8)+ch_2;
       

        ch=((tmp_val>>18) & 0x3F); 
        base_str[det_proc_len + 0] =ch_table[ch];

        ch=((tmp_val>>12) & 0x3F); 
        base_str[det_proc_len + 1] =ch_table[ch];

        ch=((tmp_val>>6) & 0x3F); 
        base_str[det_proc_len + 2] =ch_table[ch];

        ch=((tmp_val>>0) & 0x3F); 
        base_str[det_proc_len + 3] =ch_table[ch];
        

        src_proc_len = src_proc_len + 3;
        det_proc_len = det_proc_len + 4;
    }

    if(m == 1) //only 1 char
    {
        
        ch_0 = *(buf + src_proc_len + 0);
        ch_1 = 0;
        ch_2 = 0;


       tmp_val = ch_0;
       tmp_val=(tmp_val<<4);
       
       
       
        ch=((tmp_val>>6) & 0x3F); 
        base_str[det_proc_len + 0] =ch_table[ch];

        ch=((tmp_val>>0) & 0x3F); 
        base_str[det_proc_len + 1] =ch_table[ch];
        

        base_str[det_proc_len + 2] = '=';
        base_str[det_proc_len + 3] = '=';

        src_proc_len = src_proc_len + 1;
        det_proc_len = det_proc_len + 4;

    }
    else if(m == 2) //only 2 char
    {
          ch_0 = *(buf + src_proc_len + 0);
          ch_1 = *(buf + src_proc_len + 1);
          ch_2 = 0;


       tmp_val = ch_0;
       tmp_val=(tmp_val<<8)+ch_1;
       tmp_val=(tmp_val<<2);
       
       

        ch=((tmp_val>>12) & 0x3F); 
        base_str[det_proc_len + 0] =ch_table[ch];

        ch=((tmp_val>>6) & 0x3F); 
        base_str[det_proc_len + 1] =ch_table[ch];

        ch=((tmp_val>>0) & 0x3F); 
        base_str[det_proc_len + 2] =ch_table[ch];


        base_str[det_proc_len + 3] = '=';

        src_proc_len = src_proc_len + 2;
        det_proc_len = det_proc_len + 4;

    }

    
        base_str[det_proc_len] = 0;
       // printf("base64 line %d,%s\n",__LINE__,base_str);
       // exit(0);
        return base_str;

}
//-----------------------------------------------------------
int set_socket_attr(int *skt, int timeout)
{
    int reuseaddr_on = 1;
    int ret=0;
    int addr_len = 0;
#ifdef __WIN32__
   int timeo_send=1000;
   int timeo_recv=1000;

#else

    struct timeval timeo_send;
    struct timeval timeo_recv;
#endif    
    struct sockaddr_in addr;
    int len = sizeof(timeo_send);

    int nRecvBuf = 16 * 1024;       // 500*1024;              //16*1024;
    int nSendBuf = 500 * 1024;

#ifdef __WIN32__

#else

    timeo_send.tv_sec = timeout;
    timeo_send.tv_usec = 0;

    timeo_recv.tv_sec = 2 * timeout;
    timeo_recv.tv_usec = 0;
#endif
    addr_len = sizeof(reuseaddr_on);


    ret=setsockopt(*skt, SOL_SOCKET, SO_SNDTIMEO, &timeo_send, len);
   // DEBUG("set sock SO_SNDTIMEO %d\n",ret);
    ret=setsockopt(*skt, SOL_SOCKET , SO_RCVTIMEO, &timeo_recv, len);
   // DEBUG("set sock SO_RCVTIMEO %d\n",ret);


    ret=setsockopt(*skt, SOL_SOCKET, SO_REUSEADDR, &reuseaddr_on, addr_len);
   // DEBUG("set sock SO_REUSEADDR %d\n",ret);



    ret=setsockopt(*skt, SOL_SOCKET, SO_RCVBUF, (const char *)&nRecvBuf, sizeof(int));
   // DEBUG("set sock SO_RCVBUF %d\n",ret);

    ret=setsockopt(*skt, SOL_SOCKET, SO_SNDBUF, (const char *)&nSendBuf, sizeof(int));
   // DEBUG("set sock SO_SNDBUF %d\n",ret);


    return 0;
}
//------------------------------------------------------------
#ifdef __WIN32__
//-------------------------------------------------------------
int gettimeofday(struct timeval* tp, int *tz /*tz*/)  
{
   SYSTEMTIME st,stUTC,SystemTime;  
   FILETIME ft,ftUTC;
   LONGLONG diffUTC=0,k=0,i=0;
   
    memset(&st,0,sizeof(st));  
    st.wYear=1970;  
    st.wMonth=1;  
    st.wDay=1;  
    SystemTimeToFileTime(&st, &ft);  

   // GetSystemTime(&SystemTime);
      
   // base_time->LowPart = ft.dwLowDateTime;  
   // base_time->HighPart = ft.dwHighDateTime;  
   // base_time->QuadPart /= SECS_TO_FT_MULT; 

    GetSystemTime(&stUTC);
    SystemTimeToFileTime(&stUTC, &ftUTC);

  //  diffUTC=(ftUTC.dwHighDateTime<<32) +ftUTC.dwLowDateTime - (ft.dwHighDateTime<<32) -ft.dwLowDateTime;
	k=ftUTC.dwHighDateTime;
	k=(k<<32)+ftUTC.dwLowDateTime;
	i=ft.dwHighDateTime;
	i=(i<<32)+ft.dwLowDateTime;
	diffUTC=k-i;


  

   k=diffUTC/(1000*1000*10);
   tp->tv_sec=k;
   i=diffUTC-k*1000*1000*10;
   tp->tv_usec=i/10;

   return 0;
 

}
//-------------------------------------------------------------
int bzero(unsigned char *buf, int buf_len)
{
  if(buf==0 || buf_len<=0)
    return -1;

  memset(buf,0,buf_len);
}
//---------------------------------------------------------------
int create_socket(char skt_type,int skt_port)
{
      static char init_sock_lib=0;
      WSADATA  Ws;
      SOCKET ServerSocket, ClientSocket;
      struct sockaddr_in LocalAddr, ClientAddr;
      int Ret = 0;
      int AddrLen = 0;
      HANDLE hThread = NULL;
      
       int ret=-1;
       int cmdsock=-1;
       struct sockaddr_in local_addr;

        if(init_sock_lib==0)
        {
        if(WSAStartup(MAKEWORD(2,2), &Ws) != 0 )
           {
             DEBUG("Init Windows Socket Failed=%s\n",GetLastError());
             goto exit_fun;
           }
          init_sock_lib=1;
        }

       

        if(skt_type==0) //udp
       {       
          cmdsock = socket(AF_INET, SOCK_DGRAM, 0);
          if(cmdsock < 0)
          {
              DEBUG("udp socket fail \n");
              perror("cannot create socket");              
              goto exit_fun;
          }
       }
       else //tcp
       {       
          cmdsock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
          if(cmdsock < 0)
          {
              DEBUG("tcp socket fail \n");
              perror("cannot create socket");              
              goto exit_fun;
          }
       } 
       
       set_socket_attr(&cmdsock,15);
        bzero(&local_addr, sizeof(local_addr));
               local_addr.sin_family = AF_INET;
               local_addr.sin_port = htons(skt_port);
               local_addr.sin_addr.s_addr = INADDR_ANY;
               bzero(&(local_addr.sin_zero), 8);
           
               if(bind(cmdsock, (LPSOCKADDR)&local_addr, sizeof(local_addr)) == SOCKET_ERROR)
               {
                   DEBUG("rtsp tcp socket bind fail\n");
                   perror("cannot bind tcp port");
                   goto exit_fun;
               }
       
               ret=cmdsock;
       
exit_fun:
       
     if(ret<0)
     {
       if(cmdsock>=0)
        {
         shutdown(cmdsock,2);
         closesocket(cmdsock);
        }
     }
     
     return ret;
           



}

#else
int create_socket(char skt_type,int skt_port)
{
    
       
       int ret=-1;
       int cmdsock=-1;
       struct sockaddr_in local_addr;

       if(skt_type==0) //udp
       {       
          cmdsock = socket(AF_INET, SOCK_DGRAM, 0);
          if(cmdsock < 0)
          {
              DEBUG("udp socket fail \n");
              perror("cannot create socket");              
              goto exit_fun;
          }
       }
       else //tcp
       {       
          cmdsock = socket(AF_INET, SOCK_STREAM, 0);
          if(cmdsock < 0)
          {
              DEBUG("tcp socket fail \n");
              perror("cannot create socket");              
              goto exit_fun;
          }
       }
    
        set_socket_attr(&cmdsock,15);
        
        bzero(&local_addr, sizeof(local_addr));
        local_addr.sin_family = AF_INET;
        local_addr.sin_port = htons(skt_port);
        local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        bzero(&(local_addr.sin_zero), 8);
    
        if(bind(cmdsock, (struct sockaddr *)&local_addr, sizeof(local_addr)) == -1)
        {
            DEBUG("rtsp tcp socket bind fail\n");
            perror("cannot bind tcp port");
            goto exit_fun;
        }

        ret=cmdsock;

exit_fun:

    if(ret<0)
    {
      if(cmdsock>=0)
       {
        shutdown(cmdsock,2);
        close(cmdsock);
       }
    }
    
    return ret;
    

}
#endif

//----------------------------------------------------
int rtsp_check_req_end(char *in,int in_len)
{
  int i=0;
  
  if(in==0 || in_len==0 || in_len<4)
    return RTSP_ERR_FAIL;
  
  for(i=0;i<=in_len-4;i++)
  {
    if(in[i]==0x0D && in[i+1]==0x0A && in[i+2]==0x0D && in[i+3]==0x0A)
        return (i+3);
  }

  return RTSP_ERR_FAIL;

}



//---------------------------------------------------------
int rtsp_get_key_val_int(char *key_str,char *in,int in_len,char *out,int out_len)
{
   int i=0;
   int ret=RTSP_ERR_FAIL;
   unsigned int in_addr=0;
   char *tmp_str=0; 
   int head_offset=0;
   int val_len=0;

  // memset(tmp_key_val,0,sizeof(tmp_key_val));

   if(in==0 || in_len<=0 || out==0 || out_len<=0 )
     return RTSP_ERR_FAIL;

    
    memset(out,0,out_len);
    in_addr=(unsigned int)in;

   if(key_str)
   {
     tmp_str=(in,key_str);
     if(tmp_str==0)
        goto exit_fun;
  
     
     //move key string
     tmp_str=tmp_str+strlen(key_str);
     if(strlen(tmp_str)<=0)
        goto exit_fun;
   }
   else
   {
    tmp_str=in;
   }
   
   //move space and tab
   for(i=0;i<strlen(tmp_str);i++)
   {
     if(tmp_str[i]==' ' || tmp_str[i]=='\t')
        head_offset=head_offset+1;
     else
        break;

   }

   
   tmp_str=tmp_str+head_offset;
   if(strlen(tmp_str)<=0)
      goto exit_fun;


   

    for(i=0;i<strlen(tmp_str);i++)
   {
     if(tmp_str[i]=='\r' || tmp_str[i]=='\n' 
        || tmp_str[i]==' ' || tmp_str[i]==','
        || tmp_str[i]=='-' || tmp_str[i]=='_'
        || tmp_str[i]==':' || tmp_str[i]==';')
     {
        val_len=i;
        break;
     }

   }

    if(val_len<=0 || val_len>=out_len)
      goto exit_fun;


    memcpy(out,tmp_str,val_len);
    ret=RTSP_ERR_OK;

exit_fun:

    in=(char*)in_addr;
    return ret;

}



//---------------------------------------------------------
int rtsp_get_key_val(char *key_str,char *in,int in_len,char *out,int out_len)
{
   int i=0;
   int ret=RTSP_ERR_FAIL;
   unsigned int in_addr=0;
   char *tmp_str=0; 
   int head_offset=0;
   int val_len=0;

  // memset(tmp_key_val,0,sizeof(tmp_key_val));

   if(in==0 || in_len<=0 || out==0 || out_len<=0)
     return RTSP_ERR_FAIL;

    memset(out,0,out_len);
    in_addr=(unsigned int)in;

   if(key_str)
   {
      tmp_str=strstr(in,key_str);
      if(tmp_str==0)
         goto exit_fun; 
      
      //move key string  
      tmp_str=tmp_str+strlen(key_str);
      if(strlen(tmp_str)<=0)
         goto exit_fun; 
   }
   else
   {
    tmp_str=in;
   }

   
   //move space and tab
   for(i=0;i<strlen(tmp_str);i++)
   {
     if(tmp_str[i]==' ' || tmp_str[i]=='\t')
        head_offset=head_offset+1;
     else
        break;

   }

   
   tmp_str=tmp_str+head_offset;
   if(strlen(tmp_str)<=0)
      goto exit_fun; 


   

    for(i=0;i<strlen(tmp_str);i++)
   {
     if(tmp_str[i]=='\r' || tmp_str[i]=='\n' 
        || tmp_str[i]==' ' || tmp_str[i]==','
       // || tmp_str[i]=='\"' || tmp_str[i]=='\''
        || tmp_str[i]==';')
     {
        val_len=i;
        break;
     }

   }

    if(val_len<=0 || val_len>=out_len)
      goto exit_fun; 


    memcpy(out,tmp_str,val_len);
    ret=RTSP_ERR_OK;
    
    

  exit_fun:

    in=(char*)in_addr;
    return ret;
    

}

//----------------------------------------------------------
int rtsp_dateHeader(char *out,int out_len)
{

#if !defined(__WIN32__)
 // static
    char tmp_buf[200];

  char *buf=0;
 // struct tm *newtime;
  if(out==0 || out_len<=0)
    return RTSP_ERR_FAIL;
  
  memset(out,0,out_len);
  buf=out;
  

  time_t tt = time(NULL);
 // newtime=localtime(&tt);


  strftime(buf,out_len-1, "%a,%b %d %Y %H:%M:%S GMT",gmtime(&tt)); //newtime); // gmtime(&tt));
 // memcpy(buf,tmp_buf,strlen(tmp_buf))
 // DEBUG("tmp_buf=%s--%d\n",buf,strlen(buf));
  
#else
  // WinCE apparently doesn't have "time()", "strftime()", or "gmtime()",
  // so generate the "Date:" header a different, WinCE-specific way.
  // (Thanks to Pierre l'Hussiez for this code)
  // RSF: But where is the "Date: " string?  This code doesn't look quite right...
  SYSTEMTIME  SystemTime;
  char tmp_buf[200];
  char *buf=0;
 
 

  WCHAR dateFormat[] = L"ddd, MMM dd yyyy";
  WCHAR timeFormat[] = L"HH:mm:ss GMT";
  WCHAR inBuf[200];
  DWORD locale = LOCALE_SYSTEM_DEFAULT; //LOCALE_NEUTRAL;
  int ret=0;
  char *week_str[7]={"Sun","Mon","Tue","Wed","Thu","Fri","Sat"};
  char *month_str[12]={"Jan","Feb","Mar","Apr","May","Jun",
                      "Jul","Aug","Sep","Oct","Nov","Dec"};

   if(out==0 || out_len<=0)
    return RTSP_ERR_FAIL;
  
  memset(out,0,out_len);
  buf=out;

 GetSystemTime(&SystemTime);

  ret = GetDateFormat(locale, 0, &SystemTime,
                          (LPTSTR)dateFormat, (LPTSTR)inBuf, sizeof inBuf);
  inBuf[ret - 1] = ' ';
  ret = GetTimeFormat(locale, 0, &SystemTime,
                      (LPTSTR)timeFormat,
                      (LPTSTR)inBuf + ret, (sizeof inBuf) - ret);
 // ret=wcstombs(buf, inBuf, wcslen(inBuf));

   snprintf((char*)buf,out_len,
       "%s,%s %d %d %02d:%02d:%02d GMT", 
       week_str[SystemTime.wDayOfWeek],
       month_str[SystemTime.wMonth],
       SystemTime.wDay,
       SystemTime.wYear,
       SystemTime.wHour+8,
       SystemTime.wMinute,
       SystemTime.wSecond);

  
#endif
  return RTSP_ERR_OK;
}
//-------------------------------------------------------------
int move_str_space_left_right(char *in,int in_len)
{

  int i=0;
  int head_offset=0;
  int tail_offset=0;
  char *tmp_str=in;

  if(in==0 || in_len<=0)
     return RTSP_ERR_FAIL;

  //move left space and tab
   for(i=0;i<strlen(tmp_str);i++)
   {
     if(tmp_str[i]==' ' || tmp_str[i]=='\t')
        head_offset=head_offset+1;
     else
        break;

   }

   tmp_str=in+head_offset;
   if(strlen(tmp_str)>0)
   {
    for(i=strlen(tmp_str)-1;i>=0;i--)
     {
       if(tmp_str[i]==' ' || tmp_str[i]=='\t')
          tail_offset=tail_offset+1;
       else
          break;
  
     } 




   }

   if(tail_offset>0)
      memset(in+(in_len-tail_offset),0,tail_offset);
   
   if(head_offset>0)
      memmove(in,in+head_offset,in_len-head_offset);
   
   
   
      
   return RTSP_ERR_OK;


}
//--------------------------------------------------------------
unsigned long long int NTPtime64(unsigned int * out_h,unsigned int * out_l)
{
   struct timeval tv;
  
   unsigned long long int t1=0,t=0,t2=1,t4=0,t5=0;
   double t3=0.00;

   gettimeofday(&tv, NULL);
 //  printf("1== 0x%08x,0x%08x,%d\n", tv.tv_sec,tv.tv_usec,tv.tv_usec);

   t1=0x83AA7E80;
  // printf("2 1== %lld,0x%llx\n",t1,t1);
   t1=t1+tv.tv_sec;
 //  printf("2 2== %lld,0x%llx\n",t1,t1);
   t1=t1+8*3600;  //beijing UTC+8 hours  时区
  // printf("2 3== %lld,0x%llx\n",t1,t1);

   t=tv.tv_usec;
   t=t*1000*1000;
 //  printf("3== 0x%llx,%lld\n",t,t);

   
   t=t/232;
  // printf("30== 0x%llx,%lld\n",t,t);

   t2=t2<<32;
  // printf("4== 0x%llx,%lld\n",t2,t2);

   t3=(double)(1000000000000/t2);
  // printf("5== %f\n",t3);

   t4=(232.83064365386962890625*t2);
  // printf("6== %lld\n",t4);
   
    *out_h=(tv.tv_sec)+0x83AA7E80+8*3600;
    *out_l=t;

   t5=(t1<<32)+ t;


   
  // printf("7== %llx\n",t5);

  
   

    
    return t5;
}
//----------------------------------------------------------------------------
unsigned int GetTickCount_ms(unsigned int *tv_second,unsigned int *tv_ms)
{

#ifdef  __WIN32__


   #if 1
   DWORD k=GetTickCount();

   *tv_second=k/1000;
   *tv_ms=k%1000;

    #else
   
   SYSTEMTIME st,stUTC,SystemTime;  
     FILETIME ft,ftUTC;
     LONGLONG diffUTC=0,k=0,i=0;
     
      memset(&st,0,sizeof(st));  
      st.wYear=2000;//1970;  
      st.wMonth=1;  
      st.wDay=1;  
      SystemTimeToFileTime(&st, &ft);  
   
    
   
      GetSystemTime(&stUTC);
      SystemTimeToFileTime(&stUTC, &ftUTC);
   
    //  diffUTC=(ftUTC.dwHighDateTime<<32) +ftUTC.dwLowDateTime - (ft.dwHighDateTime<<32) -ft.dwLowDateTime;
      k=ftUTC.dwHighDateTime;
      k=(k<<32)+ftUTC.dwLowDateTime;
      i=ft.dwHighDateTime;
      i=(i<<32)+ft.dwLowDateTime;
      diffUTC=k-i;
   
   
    
   
     k=diffUTC/(1000*1000*10);
     //tp->tv_sec=k;
     *tv_second=k;
     i=diffUTC-k*1000*1000*10;
     //tp->tv_usec=i/10;
     *tv_ms=i/(1000*10);  
     #endif

#else
     struct timespec tv;

     // struct timeval tv;   
         
    #if 0
    unsigned int tmp_tick_H=0,tmp_tick_L=0;
    double tmp_tick_ms=0.00;
    long long cur_time_1=0,cur_time_2=0;
        
        NTPtime64(&tmp_tick_H,&tmp_tick_L);
        tmp_tick_ms=(double)((double)(tmp_tick_L)/(double)(4294967296.00));                     
        //tmp_tick_ms=tmp_tick_ms+(double)tmp_tick_H;
        //tmp_tick_ms=1000*tmp_tick_ms;

        cur_time_1=(tmp_tick_H);
        cur_time_1=cur_time_1*1000;

        cur_time_2=(tmp_tick_ms);
        cur_time_2=cur_time_2*1000;

        *cur_time_ms=cur_time_1+cur_time_2;

    #else
          // gettimeofday(&tv, NULL);
    
          clock_gettime(CLOCK_MONOTONIC,&tv);//CLOCK_MONOTONIC //此处可以判断一下返回值

       //  return (ts.tv_sec*1000 + ts.tv_nsec/(1000*1000));

         *tv_second=tv.tv_sec;
         *tv_ms=tv.tv_nsec/(1000*1000); 
        // return (ts.tv_sec);

    #endif





#endif
        
        
}
//--------------------------------------------------------------------------
int delay_ms(double msec)
{

   struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = msec * 1000;

	select(0, NULL, NULL, NULL, &tv);

	return 0;

}
//-------------------------------------------------------------------------------

