// car.cpp : 定义控制台应用程序的入口点。
//

//#include "stdafx.h"

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

void *thread_recv_data(void *p);
//-----------------------------------------------------

int main(int argc, char *argv[])
{

	CLIENT_THREAD_INFO thrd_info[10];

     int cmdsock=-1; 
     int cli_sock=-1;     
     int ret=0,i=0;     
     char tmp_ip[64]={0}; 
     char tmp_ip_local[64]={0}; 
    // struct sockaddr_in remote_addr;
     SOCKADDR_IN remote_addr;
     int remote_addr_len=sizeof(struct sockaddr_in);
 
     int free_thread_index=-1;
     unsigned char tmp_test[100]={0};

	   pthread_t recv_thrd; 

	 memset(&thrd_info,0,10*sizeof(CLIENT_THREAD_INFO));


     i=0;
	  


	 start_create_socket:

    cmdsock=create_socket(1,RTSP_PORT);
         if(cmdsock<0)
            goto start_create_socket;


    ret=listen(cmdsock,5);  
    if(ret==SOCKET_ERROR)  
    {  
        DEBUG("listen error\n");  
        shutdown(cmdsock,2);
        closesocket(cmdsock);
        cmdsock=-1;        
        goto start_create_socket;
        
    } 

	wait_client_connect:
	

     
	 cli_sock=-1;
	   free_thread_index=-1;
	   
	   cli_sock=accept(cmdsock,(SOCKADDR *)&remote_addr,&remote_addr_len);
	   if(cli_sock == INVALID_SOCKET)
		 {
		   shutdown(cli_sock,2);
		   closesocket(cli_sock);
		   cli_sock=-1; 		   
		   goto wait_client_connect;  
		}
		memset(tmp_ip,0,sizeof(tmp_ip));
		// inet_ntoa(remote_addr.sin_addr)
	 
		getpeername(cli_sock,(SOCKADDR *)&remote_addr,&remote_addr_len);
		strcpy(tmp_ip,inet_ntoa(remote_addr.sin_addr));
	   // inet_ntop(AF_INET,&remote_addr.sin_addr,tmp_ip,sizeof(tmp_ip));
		DEBUG("remote ip=%s\n",tmp_ip);

      
      if(cli_sock !=-1)
        {
		  free_thread_index=-1;
		  for(i=0;i<10;i++)
		  	{
             if(thrd_info[i].cur_free==0)
             	{
			 	free_thread_index=i;
			 	 break;
             	}


		  	}
		  if(free_thread_index==-1)
               goto exit_connect;

		
           
		   thrd_info[free_thread_index].sockfd=cli_sock; 
		   thrd_info[free_thread_index].sockfd_statue=1;
		   thrd_info[free_thread_index].remote_port=ntohs(remote_addr.sin_port);
		   memcpy(thrd_info[free_thread_index].remote_ip,tmp_ip,strlen(tmp_ip));
		   thrd_info->thread_status=1;

		   ret=pthread_create(&recv_thrd, NULL,thread_recv_data,(void*)&(thrd_info[i]));
    		 if(ret==0)
    		  {
    		   thrd_info->thread_status=2;
			   thrd_info[free_thread_index].cur_free=1;			   
    		  }



		   
          
         }

	       goto wait_client_connect; 

        exit_connect:

	    if(cli_sock !=-1)		
	    	{
	     shutdown(cli_sock,2);
		 closesocket(cli_sock);
		 cli_sock=-1;
	    	}
    
     //  DEBUG("accept cli socket error--%d--%d!!!\n",cli_sock,errno);          
       goto wait_client_connect; 


	WSACleanup();
    

	return 0;
}

//----------------------------------------------------
int proc_recv_data(unsigned char *buf,int buf_len,CLIENT_THREAD_INFO *thread_info)
{

  int rtp_protocol=0;  

  unsigned char *data=0;

  int ret=0,i=0;
  int offset_sync=0;
  char find_sync_flag=0;

  int rtp_pack_len=0;
  char ual_type_tmp=0;
  char ual_type_name=0;

  char in_data_is_short=0;
  int kkk=0;
  char force_exit=0;

  char recoder_str[100]={0};

  
 

  unsigned int recv_pack_no = 0;


  
	ret=buf_len;
	data=buf;

	if(ret==0 || data==0)
		return 0;

if(rtp_protocol==0) //tcp
{
  
proc_start:

	   find_sync_flag = 0;
	   offset_sync = 0;

	   if(ret<0)
	   {
		  return 0;
	   }

	   if(in_data_is_short)
	   {
		 return ret;
	   }
	   
	   if(force_exit)
		{
		 return ret;
		}
	   
	   
	   if(ret<4)
	   {
		  return ret;
	   }
	   //ret>16
	   
  // printf("find_frame_stream_ma_2 run line=%d offset_sync=%d index=%d ret=%d\n",
  // __LINE__,offset_sync,index,ret);  
	   
	for(offset_sync = 0; offset_sync <= ret - 4; offset_sync++)
	 {
			  if( data[offset_sync] == 0x77
				 &&  data[offset_sync + 1] == 0x55
				 && data[offset_sync + 2] == 0x77
				 && data[offset_sync + 3] == 0x55
				)
			  {
				 //find 0x24 sync head
				 find_sync_flag = 1;
				 
				// printf("find_frame_stream_ma_2 run line=%d offset_sync=%d index=%d\n",__LINE__,offset_sync,index);  
				 
                        #if 0
							if(offset_sync)
								{
									for(kkk=0;kkk<offset_sync;kkk++)
									{
							printf("mamam run line=%d ret=%d kkk=%d offset_sync=%d "\
								"val:0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x\n",
										__LINE__,ret,kkk,
									   offset_sync,
									   data[kkk],
									   data[kkk+1],
									   data[kkk+2],
									   data[kkk+3],
									   data[kkk+4],
									   data[kkk+5]);
									}
								}
                        #endif
								
				 
				 break;
			  }


	 }



	if(offset_sync > 0)
	{
	 // printf("find_frame_stream_ma_2 run line=%d offset_sync=%d index=%d\n",__LINE__,offset_sync,index);	
	  
#if 0
	  if(offset_sync)
		  {
			  for(kkk=0;kkk<offset_sync;kkk++)
			  {
	  printf("mamam run line=%d ret=%d kkk=%d offset_sync=%d "\
		  "val:0x%02x,0x%02x,0x%02x,0x%02x,0x%02x,0x%02x\n",
				  __LINE__,ret,kkk,
				 offset_sync,
				 data[kkk],
				 data[kkk+1],
				 data[kkk+2],
				 data[kkk+3],
				 data[kkk+4],
				 data[kkk+5]);
			  }
		  }
#endif

	  data=data+offset_sync;
	  ret=ret-offset_sync;
	  goto proc_start;
	}
	
	if(find_sync_flag == 0)
	{
	  //return ret; //not find sync head, continue recv tcp pack
	  DEBUG("find_frame_stream_ma_2 run line=%d\n",__LINE__);
	}

	
			
	 // find sync head			 
	rtp_pack_len = 0; 
    memset(recoder_str,0,sizeof(recoder_str));
	 for(i=0;i<=ret-4;i++)
      {
        if(data[i]==0x0D && data[i+1]==0x0A && data[i+2]==0x0D && data[i+3]==0x0A)
        	{
            rtp_pack_len=(i+4);
			thread_info->send_respon_flag=1;
			break;
        	}
      }
	
	 if(rtp_pack_len>0)
	 	{
		 memcpy(recoder_str,data,rtp_pack_len);
         DEBUG("recv car info=%s\n",recoder_str);
		 
		 data=data+rtp_pack_len;
		 ret=ret-rtp_pack_len;
		// goto proc_start;		 
	 	}
	 else
	 	{
          if(ret>500)  //500 len no find recoder,it is error pack
		  	 ret=0;


	 	}
	
  goto proc_start; 
}


}


//------------------------------------------------------------------
void *thread_recv_data(void *p)
{


    CLIENT_THREAD_INFO *thread_info=0;

    fd_set fd_rd,fd_wr;    
    struct timeval tvout;
	 int tid_statue=0;

    
    int tv = 0;
    int epfds = -1;
    int epfd = -1;    
    int ret=-1,i=0;
    unsigned char *recv_data=0;
    unsigned char *send_data=0;
   
   pthread_detach(pthread_self());

    thread_info=(CLIENT_THREAD_INFO*)p;

	if(thread_info->sockfd<=0)
          return 0;




	

  while(thread_info->thread_status<2)
  	{
  	delay_ms(20);
  	}
  thread_info->thread_status=3;


  init_recv_data_buf: 

	 
       
       if(recv_data==0)
        {
          recv_data=(unsigned char*)malloc(RECV_BUF_MAX_LEN);
          if(recv_data<=0)
          {
             DEBUG("malloc data fail err_id:%d\n",errno);
            delay_ms(200);
            goto init_recv_data_buf;
          }  
        }
    
         thread_info->recv_buf=recv_data;
         thread_info->recv_buf_max_len=RECV_BUF_MAX_LEN;
         thread_info->recv_buf_left_len=0;

   init_send_data_buf: 
       
       if(send_data==0)
        {
          send_data=(unsigned char*)malloc(SEND_BUF_MAX_LEN);
          if(send_data<=0)
          {
             DEBUG("malloc send_data fail err_id:%d\n",errno);
            delay_ms(200);
            goto init_send_data_buf;
          }  
        }
       
       thread_info->send_buf=send_data; //response rtsp cmd
       thread_info->send_buf_max_len=SEND_BUF_MAX_LEN;
       thread_info->send_buf_left_len=0;
	   
   

 
  tv = 15; 
  ret=-1;
  epfds=-1;
  
  
  while(1)
    {
      delay_ms(20);
      

      tvout.tv_sec=1;
      tvout.tv_usec=0;

      FD_ZERO(&fd_rd);
      FD_ZERO(&fd_wr);
      FD_SET(thread_info->sockfd,&fd_rd); 
      FD_SET(thread_info->sockfd,&fd_wr);
      
      epfds=select(0, &fd_rd, &fd_wr, NULL, &tvout);
      if(epfds == SOCKET_ERROR)
          {           
           DEBUG("fd_check_new epfds:%d,err_id:%d\n", epfds, errno);
           perror("fd_check_new error");
          // goto free_connect;
		   continue;
         }
         else if(epfds == 0) //timeout
         {
           DEBUG("fd_check_new epfds:%d,err_id:%d\n", epfds, errno);
           perror("fd_check_new timeout error");
           continue;
         }

       if(0==FD_ISSET(thread_info->sockfd,&fd_rd) && 0==FD_ISSET(thread_info->sockfd,&fd_wr)) //no read,no write
        {
           DEBUG("fd_check_new epfds:%d,err_id:%d\n", epfds, errno);
           perror("fd_check_new socket error");
           continue;
        }

      
       if(ret=FD_ISSET(thread_info->sockfd,&fd_rd)) //recv
         {
            // DEBUG("ma\n");

           
            if(thread_info->recv_buf_left_len>=thread_info->recv_buf_max_len || thread_info->recv_buf_left_len<0)
                   thread_info->recv_buf_left_len=0;
               
                       
               ret=recv(thread_info->sockfd,(char*)thread_info->recv_buf+thread_info->recv_buf_left_len,thread_info->recv_buf_max_len-thread_info->recv_buf_left_len,0); // | MSG_PEEK); // MSG_WAITALL | MSG_PEEK);
               if(ret <=0) //disconnect
               {
                   DEBUG("recv client sock disconnect errid=%d\n",errno);
                   thread_info->sockfd_statue=2;
                   goto free_connect;
               }
               thread_info->recv_buf_left_len=thread_info->recv_buf_left_len+ret;
			   i=proc_recv_data(thread_info->recv_buf,thread_info->recv_buf_left_len,thread_info);
			   if(i>0)
			   	 memmove(thread_info->recv_buf,thread_info->recv_buf+thread_info->recv_buf_left_len-i,i);
			   
               thread_info->recv_buf_left_len=i;

           
         }
     
      if(ret=FD_ISSET(thread_info->sockfd,&fd_wr)) //send
      {
       if(thread_info->send_respon_flag==1)
    	{
			printf("hhhhh\n");
    	thread_info->send_buf[0]=0x88;
		thread_info->send_buf[1]=0x66;
		thread_info->send_buf[2]=0x88;
		thread_info->send_buf[3]=0x66;
		
        ret=send(thread_info->sockfd,(char*)thread_info->send_buf,4,0);
		if(ret>0)
			thread_info->send_respon_flag=0;

    	}
          
      }
      
      

   
    }
    
    
    
    
free_connect: 

      DEBUG("cur remote client disconnect ip=%s sock=%d===%d\n",
        thread_info->remote_ip,
        thread_info->sockfd,epfd);


     // ret = epoll_ctl(epfd,EPOLL_CTL_DEL,thread_info->sockfd,&event);
     // close(epfd);

      if(thread_info->sockfd !=-1)
      {
       shutdown(thread_info->sockfd,2);
       closesocket(thread_info->sockfd);
      }
      thread_info->sockfd=-1;
      thread_info->sockfd_statue=0;

     

    if(thread_info->recv_buf)  
        free(thread_info->recv_buf);
    
    thread_info->recv_buf=0;

    if(thread_info->send_buf)  
        free(thread_info->send_buf);
    
    thread_info->send_buf=0;


	 thread_info->thread_status=0; 

	 thread_info->cur_free=0;	
  	
   pthread_exit((void *)&tid_statue);
	 
  

 return 0;

}
//---------------------------------------------------------



