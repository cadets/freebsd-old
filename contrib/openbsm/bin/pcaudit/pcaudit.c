/* Copyright (c) 2016 BAE Systems
 * All rights reserved.
 *
 * This software was developed by BAE Systems, the University of Cambridge
 * Computer Laboratory, and Memorial University under DARPA/AFRL contract
 * FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
 * (TC) research program.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */
#include<stdlib.h>
#include<bsm/libbsm.h>
#include<arpa/inet.h>

void print_token(tokenstr_t*);
void print_string(char*);

int main(int argc, char** argv)
{
    if (argc <= 1) {
        printf("usage: %s [files]\n", argv[0]);
        return 1;
    }

    u_char** buffer = (u_char**) malloc(sizeof(u_char*));
    tokenstr_t* token = (tokenstr_t*) malloc(sizeof(tokenstr_t));
    for(int i=1; i<argc; i++)
    {
        FILE* file = fopen(argv[i], "r");
        int record_length;

        if(buffer == NULL) {
            printf("Null buffer.\n");
            return -1;
        }
        if(file == NULL) {
            printf("Null file.\n");
            return -1;
        }
        while((record_length = au_read_rec(file, buffer)) > 0)
        {
            int bytes_read = 0;
            while(bytes_read < record_length)
            {
                if((au_fetch_tok(token, (*buffer)+bytes_read, record_length - bytes_read)) == -1)
                {
                    break;
                }
                print_token(token);
                bytes_read += token->len;
            }

            free(*buffer);
        }
    }

    return 0;
}

void print_token(tokenstr_t* t)
{
	struct in_addr ipaddr;
    switch(t->id)
    {
//     case AUT_ARG32:
//     case AUT_ARG64:
//     case AUT_ATTR32:
//     case AUT_ATTR64:
//     case AUT_DATA:
    case AUT_EXEC_ARGS:
        printf(", \"args\": \"");
        for(u_int32_t i = 1; i < t->tt.execarg.count; i++) {
            if(i > 1) printf(" ");
            print_string( t->tt.execarg.text[i]);
        }
        printf("\"");
        break;
//     case AUT_EXEC_ENV:
//     case AUT_EXIT:
    case AUT_HEADER32:
		// ae_name is ugly, but does not seem to have spaces
		// ae_desc is more human-readable, but doesn't have a specific format
        printf("{\"event\":\"audit::%s:\", \"time\": %d%03d000000", getauevnum(t->tt.hdr32.e_type)->ae_desc, t->tt.hdr32.s, t->tt.hdr32.ms);
        break;
    case AUT_HEADER32_EX:
        printf("{\"event\":\"audit::%s:\", \"time\": %d%03d000000", getauevnum(t->tt.hdr32_ex.e_type)->ae_desc, t->tt.hdr32_ex.s, t->tt.hdr32.ms);
        break;
    case AUT_HEADER64:
        printf("{\"event\":\"audit::%s:\", \"time\": %ld%03d000000", getauevnum(t->tt.hdr64.e_type)->ae_desc, t->tt.hdr64.s, t->tt.hdr32.ms);
        break;
    case AUT_HEADER64_EX:
        printf("{\"event\":\"audit::%s:\", \"time\": %ld%03d000000", getauevnum(t->tt.hdr64_ex.e_type)->ae_desc, t->tt.hdr64_ex.s,t->tt.hdr32.ms);
        break;
    case AUT_IN_ADDR: ;
        ipaddr.s_addr = t->tt.inaddr.addr;
        printf(", \"address\":\"%s\"", inet_ntoa(ipaddr)); // should probably use path.len as well
        break;
//     case AUT_IN_ADDR_EX: ;
//         ipaddr.s_addr = t->tt.inaddr.addr;
//         printf(", \"address\":\"%s\"", inet_ntoa(ipaddr)); // should probably use path.len as well
//         break;
//     case AUT_IP:
//     case AUT_IPC:
//     case AUT_IPC_PERM:
//     case AUT_IPORT:
//     case AUT_NEWGROUPS:
//     case AUT_OPAQUE:
    case AUT_OTHER_FILE32:
        printf(", \"file\":\"%s\"", t->tt.file.name); // should probably use path.len as well
        break;
    case AUT_PATH:
        printf(", \"path\":\"%s\"", t->tt.path.path); // should probably use path.len as well
        break;
//     case AUT_PRIV:
//     case AUT_PROCESS32:
//     case AUT_PROCESS32_EX:
//     case AUT_PROCESS64:
//     case AUT_PROCESS64_EX:
//     case AUT_RETURN32:
//     case AUT_RETURN64:
//     case AUT_SEQ:
//     case AUT_SOCKET:
//     case AUT_SOCKET_EX:
//     case AUT_SOCKINET128:
    case AUT_SOCKINET32:
        ipaddr.s_addr = t->tt.sockinet_ex32.addr[0];
        printf(", \"address\": \"%s\", \"port\": %d", inet_ntoa(ipaddr), t->tt.sockinet_ex32.port);
	break;
//     case AUT_SOCKUNIX:
//         printf(", \"address\": %d", t->tt.sockunix.path);
// 	break;
    case AUT_SUBJECT32:
        printf(", \"uid\": %d, \"pid\": %d, \"tid\": %u", t->tt.subj32.ruid, t->tt.subj32.pid, t->tt.subj32.tid.port); // which uid should I use? real, effective, etc - what tid should I use?
        break;
    case AUT_SUBJECT32_EX:
        printf(", \"uid\": %d, \"pid\": %d, \"tid\": %u", t->tt.subj32_ex.ruid, t->tt.subj32_ex.pid, t->tt.subj32_ex.tid.port); // which uid should I use? real, effective, etc
        break;
    case AUT_SUBJECT64:
        printf(", \"uid\": %d, \"pid\": %d, \"tid\": %lu", t->tt.subj64.ruid, t->tt.subj64.pid, t->tt.subj64.tid.port); // which uid should I use? real, effective, etc
        break;
    case AUT_SUBJECT64_EX:
        printf(", \"uid\": %d, \"pid\": %d, \"tid\": %lu", t->tt.subj64_ex.ruid, t->tt.subj64_ex.pid, t->tt.subj64_ex.tid.port); // which uid should I use? real, effective, etc
        break;
//     case AUT_TEXT:
    case AUT_TRAILER:
        printf(" }\n");
        break;
//     case AUT_UPRIV:
//     case AUT_ZONENAME:
    default:
        break;
//         au_print_flags_tok(stdout, t, ",", 0);
    }
}

void print_string(char* str)
{
	while(*str != 0)
	{
		switch(*str)
		{
			case '\"':
				printf("\\\"");
				break;
			default:
				printf("%c", *str);

		}
		str++;
	}
}
