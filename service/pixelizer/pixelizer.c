#include <sys/socket.h>
#include <sys/sendfile.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>

#define BUF_LEN 1000											//length of buffer frame, bytes
#define IMG_LEN 42000											//length of image frame, bytes

void main() {
	int s = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr = {
		AF_INET,
		0x901f,										//Port number (8080 in hex)
		0											//IPv4 address
	};
	
	bind(s, &addr, sizeof(addr));
		
	listen(s, 1000);										//socket, number of simultaneous connections
	
	while(1) {		
		int client_fd = accept(s, 0, 0);							//Get client socket number
		char* buf = (char*)calloc(BUF_LEN+1,sizeof(char));					//Buffer for data (+null in the end)
		recv(client_fd, buf, BUF_LEN, 0);						//client, buffer, length, flags (unused)

		char* pic_name;									//Original image, adds "og_" in front
		char* out_name;									//Name of the image
		int name_len = 0;
		for(;buf[name_len];name_len++);							//While bytes are non-zero, it is a name
		name_len++;										//Null terminator
		
		pic_name = (char*)calloc(name_len+3,sizeof(char));
		pic_name[0] = 'o';
		pic_name[1] = 'g';
		pic_name[2] = '_';
		out_name = (char*)calloc(name_len,sizeof(char));
		
		for(int i=0;i<name_len;i++) {
			pic_name[i+3] = buf[i];
			out_name[i] = buf[i];
			buf[i] = 0;
		}
		for(int i=name_len;i<BUF_LEN;i++) {							//Clean the buffer in case name had a null byte and got cut off
			buf[i]=0;
		}
		
		FILE* client_img = fopen(pic_name, "wb");
		if(!client_img) {
			send(client_fd, "E: Write Error!\n",17,0);
			close(client_fd);
			free(pic_name);
			free(out_name);
			free(buf);
			continue;
		}
		
		send(client_fd, "OK", 3, 0);

		if(buf)
			free(buf);
		
		buf = (char*)calloc(IMG_LEN, sizeof(char));
		
		int fin_size = 0;									//Size of last frame
		
		recv(client_fd, buf, IMG_LEN, 0);
		
		if(buf[0] != 'B' || buf[1] != 'M') {
			send(client_fd, "E: Not a BMP!\n", 15, 0);
			fclose(client_img);
			close(client_fd);
			free(pic_name);
			free(out_name);
			free(buf);
			continue;
		}
		for(int j=5;j>1;j--)
			fin_size = fin_size * 256 + (int)(buf[j]);
		
		int frame_num = (fin_size+IMG_LEN-1)/IMG_LEN;
		for(int j=0;j<IMG_LEN;j++)
			fprintf(client_img,"%c", buf[j]);
		
		for(int f_id=1; f_id<frame_num;f_id++){
			recv(client_fd, buf, IMG_LEN, 0);

			if(f_id == frame_num-1) {							//Last frame, need size
				for(int j=0;j<fin_size % IMG_LEN;j++)
					fprintf(client_img,"%c", buf[j]);
			} else {
				for(int j=0;j<IMG_LEN;j++)
					fprintf(client_img,"%c", buf[j]);
			}
		}
		
		fclose(client_img);
		free(buf);
		
		FILE* out_img = fopen(out_name, "wb");
		if(!out_img) {
			send(client_fd, "E: Write Error!\n",17,0);
			close(client_fd);
			free(pic_name);
			free(out_name);
			continue;
		}
		fclose(out_img);									//File created, close it
		
		char* command = (char*)calloc(14+(name_len+2)+14+(name_len-1)+2,sizeof(char));	//ffmpeg -y -i '[INPUT]' -s 100x100 '[OUTPUT]', add null terminator
		command[0] ='f';
		command[1] ='f';
		command[2] ='m';
		command[3] ='p';
		command[4] ='e';
		command[5] ='g';
		command[6] =' ';
		command[7] ='-';
		command[8] ='y';
		command[9] =' ';
		command[10] ='-';
		command[11] ='i';
		command[12] =' ';
		command[13] ='\'';
		for(int i=0;i<name_len+2;i++)
			command[14+i] = pic_name[i];
		command[16+name_len] ='\'';
		command[17+name_len] =' ';
		command[18+name_len] ='-';
		command[19+name_len] ='s';
		command[20+name_len] =' ';
		command[21+name_len] ='1';
		command[22+name_len] ='0';
		command[23+name_len] ='0';
		command[24+name_len] ='x';
		command[25+name_len] ='1';
		command[26+name_len] ='0';
		command[27+name_len] ='0';
		command[28+name_len] =' ';
		command[29+name_len] ='\'';
		for(int i=0;i<name_len-1;i++)
			command[30+name_len+i] = out_name[i];
		command[29+2*name_len] ='\'';
		command[30+2*name_len] ='\0';
		
		system(command);
		free(command);
		remove(pic_name);
		free(pic_name);
		
		int out_fd = open(out_name, O_RDONLY);
		sendfile(client_fd, out_fd, 0, IMG_LEN);
		
		close(out_fd);
		close(client_fd);
		free(out_name);
	}
	close(s);
	return;
}
