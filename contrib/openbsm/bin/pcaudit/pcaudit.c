
#include<stdio.h>
#include<stdlib.h>
#include<bsm/libbsm.h>
#include<arpa/inet.h>

void print_token(tokenstr_t*);

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
    switch(t->id)
    {
//     case AUT_ARG32:
//     case AUT_ARG64:
//     case AUT_ATTR32:
//     case AUT_ATTR64:
//     case AUT_DATA:
    case AUT_EXEC_ARGS:
        printf(", \"args\":\"");
        for(u_int32_t i = 0; i < t->tt.execarg.count; i++) {
            if(i >= 0) printf(" ");
            printf("%s", t->tt.execarg.text[i]);
        }
        printf("\"");
        break;
//     case AUT_EXEC_ENV:
//     case AUT_EXIT:
    case AUT_HEADER32:
        printf("{\"event\":\"audit::%d:\", \"time\": %d%03d000000", t->tt.hdr32.e_type, t->tt.hdr32.s, t->tt.hdr32.ms);
        break;
    case AUT_HEADER32_EX:
        printf("{\"event\":\"audit::%d:\", \"time\": %d%03d000000", t->tt.hdr32_ex.e_type, t->tt.hdr32_ex.s, t->tt.hdr32.ms);
        break;
    case AUT_HEADER64:
        printf("{\"event\":\"audit::%d:\", \"time\": %ld%03d000000", t->tt.hdr64.e_type, t->tt.hdr64.s, t->tt.hdr32.ms);
        break;
    case AUT_HEADER64_EX:
        printf("{\"event\":\"audit::%d:\", \"time\": %ld%03d000000", t->tt.hdr64_ex.e_type, t->tt.hdr64_ex.s,t->tt.hdr32.ms);
        break;
    case AUT_IN_ADDR: ;
        struct in_addr ipaddr;
        ipaddr.s_addr = t->tt.inaddr.addr;
        printf(", \"address\":\"%s\"", inet_ntoa(ipaddr)); // should probably use path.len as well
        break;
//     case AUT_IN_ADDR_EX: ;
//         struct in_addr ipaddr_ex;
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
//     case AUT_SOCKINET32:
//     case AUT_SOCKUNIX:
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
