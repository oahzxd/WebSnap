#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <zlib.h>
#include <assert.h>
#include <sys/time.h>

#define True 1
#define False 0
#define MAX_CHAR_IN_LINE 5000


#define MAX_PATH_LEN 1024
#define MAX_NAME_LEN 200
#define MAX_NAME_NUM 512

char File_Names[MAX_NAME_NUM][MAX_NAME_LEN];
int name_cnt = 0;

int remove_file(char *file_name) {
    remove(file_name);  
    return 0;  
}
    

int get_random_num()
{
    static int r = 1;
    struct timeval tv;
    struct timezone tz;
    gettimeofday(&tv, &tz);
    return tv.tv_sec + (r++);
}

void list_all_files(char *dirname)
{
    assert(dirname != NULL);
    
    char path[512];
    struct dirent *filename;
    DIR *dir;
    
    dir = opendir(dirname);
    if(dir == NULL)
    {
        printf("open dir %s error!\n",dirname);
        exit(1);
    }
    
    while((filename = readdir(dir)) != NULL)
    {
        if(!strcmp(filename->d_name,".") || !strcmp(filename->d_name,".."))
            continue;

        if (strstr(filename->d_name, "tmp") != NULL) {
            strncpy(File_Names[name_cnt++], filename->d_name, MAX_NAME_NUM);
        }
    }
    closedir(dir);
}

int inflate_zlib(unsigned char* data, u_int32_t length, unsigned char* decompressed, u_int32_t maxDecompressed)
{
    z_stream infstream;
    infstream.zalloc = Z_NULL;
    infstream.zfree = Z_NULL;
    infstream.opaque = Z_NULL;
    infstream.avail_in = length;
    infstream.next_in = data;
    infstream.avail_out = maxDecompressed;
    infstream.next_out = decompressed;
    inflateInit2(&infstream, 32);
    inflate(&infstream, Z_FINISH);
    inflateEnd(&infstream);
    return infstream.total_out;
}

char *strnstr(const char *haystack, const char *needle, size_t len)
{
    int i;
    size_t needle_len;
    if (0 == (needle_len = strlen(needle)))
        return (char *)haystack;
    
    for (i=0; i<=(int)(len-needle_len); i++)
    {
        if ((haystack[0] == needle[0]) &&
            (0 == strncmp(haystack, needle, needle_len)))
            return (char *)haystack;
        
        haystack++;
    }
    return NULL;
}

int get_value(FILE *fd, char *s_sign, char *e_sign, char *ret)
{
    int r = False;
    char line[MAX_CHAR_IN_LINE] = {0};
    while (fgets(line, MAX_CHAR_IN_LINE, fd) != NULL) {
        char *start = strstr(line, s_sign);
        if (start != NULL) {
            char *end = strstr(line, e_sign);
            if (end != NULL) {
                char *pt = NULL;
                int i = 0;
                for (pt = start + strlen(s_sign); pt != end; pt++) {
                    ret[i++] = *pt;
                }
                r = True;
                break;
            }
        }
    }
    return r;
}

int get_file_len(FILE *fd)
{
    int len = 0;
    char len_str[MAX_CHAR_IN_LINE] = {0};
    get_value(fd, "Content-Length: ", "\r\n", len_str);
    len = atoi(len_str);
    return len;
}

void move_to_content(FILE *fd)
{
    char line[MAX_CHAR_IN_LINE] = {0};
    while (fgets(line, MAX_CHAR_IN_LINE, fd) != NULL) {
        char *sign = "\r\n";
        if (strcmp(sign, line) == 0) {
            break;
        }
    }
    return;
}

int find_gzip_sign(FILE *fd, char *line, int *line_len)
{
    int ret = False;
    int cnt = 5; // find gzip sign in 5 lines.
    int last_len = ftell(fd);
    while (fgets(line, MAX_CHAR_IN_LINE, fd) != NULL && cnt != 0) {
        *line_len = ftell(fd) - last_len;
        last_len = ftell(fd);
        if ((line[0] & 0xff) == 0x1f &&
            (line[1] & 0xff) == 0x8b &&
            (line[2] & 0xff) == 0x08 &&
            (line[3] & 0xff) == 0x00) {
            ret = True;
            break;
        }
        cnt--;
        memset(line, 0, MAX_CHAR_IN_LINE);
    }
    return ret;
}

int get_total_len(FILE *fd)
{
    char len_str[MAX_CHAR_IN_LINE] = {0};
    if (get_value(fd, "[len=", "]--", len_str) == True) {
        int len = atoi(len_str);
        return len;
    }
    return 0;
}

int get_file_name(FILE *fd, char *file_name)
{
    int ret = False;
    char file_name_str[MAX_CHAR_IN_LINE] = {0};
    get_value(fd, "GET ", " HTTP", file_name_str);
    char *start = strrchr(file_name_str, '/');
    if (start != NULL) {
        strcpy(file_name, start + 1);
        if (strlen(file_name) == 0) {
            snprintf(file_name, MAX_NAME_LEN, "%d", get_random_num());
        }
        printf("file_name is %s\n", file_name);
        ret = True;
    }
    return ret;
}

int check_header(FILE *fd, int *is_compress, int *is_html)
{
    int ret = True;
    char line[MAX_CHAR_IN_LINE] = {0};
    int not_found = True;
    while (fgets(line, MAX_CHAR_IN_LINE, fd) != NULL) {
        char *stop_sign = "\r\n";
        char *type = NULL;
        /* if (strstr(line, "302") != NULL || */
        /*     strstr(line, "301") != NULL || */
        /*     strstr(line, "404") != NULL) { */
        /*     ret = False; */
        /*     break; */
        /* } */
        if (strcmp(stop_sign, line) == 0) {
            break;
        }
        if (strstr(line, "Content-Encoding: gzip") != NULL) {
            printf("pack is use gzip!\n");
            *is_compress = True;
            not_found = False;
            continue;
        }
        if ((type = strstr(line, "Content-Type")) != NULL) {
            printf("file-type=%s", line + strlen("Content-Type"));
            if (strstr(type, "html") != NULL) {
                *is_html = True;
            }
            not_found = False;
            continue;
        }
    }
    if (not_found == True) {
        printf("not found info in header\n");
    }
    return ret;
}

int check_compress(FILE *fd)
{
    int ret = False;
    char line[MAX_CHAR_IN_LINE] = {0};
    while (fgets(line, MAX_CHAR_IN_LINE, fd) != NULL) {
        char *stop_sign = "\r\n";
        if (strcmp(stop_sign, line) == 0) {
            break;
        }
        if (strstr(line, "Content-Encoding: gzip") != NULL) {
            ret = True;
            break;
        }
    }
    return ret;
}


int is_html_packet(char *file_name)
{
    char *start = strrchr(file_name, '.');
    if (start != NULL) {
        if (strcmp("html", start+1) == 0) {
            return True;
        }
    }
    return False;
}

int is_folder_exist(const char* path)
{
    DIR *dp = NULL;
    if ((dp = opendir(path)) == NULL) {
        return False;
    }
    closedir(dp);
    return True;
}


void convert(char *filename)
{
    FILE *fd = fopen(filename, "rb");
    if (fd == NULL) {
        printf("open file:%s failed!", filename);
        return;
    }
    char fold_name[MAX_CHAR_IN_LINE] = "./html_files";
    if (is_folder_exist(fold_name) == False) {
        mkdir(fold_name, S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH);
    }
    while (feof(fd) == 0) {
        // get info
        FILE *tmp_fd = fd;
        long recv_pack_len = 0;
        recv_pack_len = get_total_len(fd); //--[len=%d]--\r\n
        if (recv_pack_len == 0) {
            continue;
        }
        char file_name[MAX_CHAR_IN_LINE] = {0};
        if (get_file_name(fd, file_name) == False) {
            char *buff = malloc(recv_pack_len);
            fread(buff, 1, recv_pack_len, fd);
            free(buff);
            printf("get_file_name failed!\n");
            continue;
        }
        move_to_content(fd);
        int header_len = ftell(fd);
        int is_compress = False;
        int is_html = False;
        if (check_header(fd, &is_compress, &is_html) == False) {
            continue;
        }
        if (is_html == True) {
            if (strstr(file_name, ".html") == NULL) {
                strcat(file_name, ".html");
                printf("change name to %s\n", file_name);
            }
        }
        header_len = ftell(fd) - header_len;
        printf("recv_pack_len = %d\n", recv_pack_len);
        int content_len = recv_pack_len - header_len - 6;
        if (content_len <= 0) {
            printf("content len is 0!\n");
            continue;
        }
        int line_len = 0;
        u_int32_t len = content_len;
        // gzip uncompress
        if (is_compress == True) {
            char line[MAX_CHAR_IN_LINE] = {0};
            if (find_gzip_sign(fd, line, &line_len) == True) {
                // printf("find gzip sign!, content_len=%d line_len=%d\n", content_len, line_len);
                char *compress_buff = malloc(content_len);
                memset(compress_buff, 0, content_len);
                if (line_len > content_len) {
                    memcpy(compress_buff, line, content_len);
                } else {
                    memcpy(compress_buff, line, line_len);
                    fread(compress_buff + line_len, 1, content_len - line_len, fd);
                }
                char *buff = malloc(content_len * 20);
                memset(buff, 0, content_len * 20);
                printf("uncompress len = %d\n", len);
                len = inflate_zlib(compress_buff, content_len, buff, content_len * 20);
                printf("compress len = %d\n", len);
                //assert(len > 0);
                if (len <= 0) {
                    free(compress_buff);
                    free(buff);
                    continue;
                }
                FILE *dest = fopen("./newout","wb");
                fwrite(buff, 1, len, dest);
                fclose(dest);
                tmp_fd = fopen("./newout","rb");
                free(compress_buff);
                free(buff);
            }
        }
        printf("get info done!\n");
        char *buff = NULL;
        int offset = 0;
        char path[MAX_CHAR_IN_LINE * 2] = {0};
        if (is_html == False) {
            buff = malloc(len);
            memset(buff, 0, len);
            snprintf(path, MAX_NAME_LEN, "%s/%s", fold_name, file_name);
            printf("not html path=%s, len=%d\n", path, len);
            struct stat stat_buff;
            if (stat(path, &stat_buff) == 0) {
                snprintf(path, MAX_NAME_LEN, "%s/%d_%s", fold_name, get_random_num(), file_name);
                printf("HAVE SAME NAME FILE!! rename=%s\n", path);
            }
            FILE *output = fopen(path, "w");
            fread(buff, len, 1, tmp_fd);
            fwrite(buff, len, 1, output);
            fclose(output);
            output = NULL;
            free(buff);
        } else {
            buff = malloc(len + 1000);
            memset(buff, 0, len + 1000);
            strncpy(path, file_name, MAX_NAME_LEN);
            printf("html save path =%s, pack len is = %d\n", path, len);
            long p1 = ftell(tmp_fd);
            int html_head_over = False;
            
            while (len != 0 && ((ftell(tmp_fd) - p1) < len)) {
                //printf("ftell(tmp_fd) - p1 = %d, len = %d\n", ftell(tmp_fd) - p1, len);
                char line[MAX_CHAR_IN_LINE] = {0};
                char new_line[MAX_CHAR_IN_LINE] = {0};
                assert(fgets(line, MAX_CHAR_IN_LINE, tmp_fd) != NULL);

                if (html_head_over == False) {
                    char *start = NULL;
                    int need_change = False;
//                    memcpy(new_line, line, MAX_CHAR_IN_LINE);
//                    char *end = new_line;
                    char *end = line;
                    int line_offset = 0;
                    int new_line_offset = 0;
                    while ((start = strstr(end, "href=")) != NULL) {
                        end = strstr(start, ">");
                        if (end != NULL) {
                            if (end - start >= MAX_CHAR_IN_LINE) {
                                printf("-bbbb212222-\n");
                                break;
                            }
                            char *sign = strstr(start, ".");
                            char *name = sign;
                            if (sign != NULL) {
                                while ((*name) != '/' && (*name) != '=' && (*name) != '\"') {
                                    name--;
                                }
                                if ((*name) == '/') {
                                    need_change = True;
                                    strncpy(new_line + new_line_offset, line + line_offset, start - (line + line_offset));
                                    new_line_offset += start - (line + line_offset);
                                    if (strnstr(start, "/", sign - start) != NULL) {
                                        strncpy(new_line + new_line_offset, "href=\"", 6);
                                        new_line_offset += 6;
                                    } else {
                                        strncpy(new_line + new_line_offset, "href=", 5);
                                        new_line_offset += 5;
                                    }
                                    strncpy(new_line + new_line_offset, fold_name, strlen(fold_name));
                                    new_line_offset += strlen(fold_name);
                                    strncpy(new_line + new_line_offset, name, sign - name);
                                    new_line_offset += sign - name;
                                    strncpy(new_line + new_line_offset, sign, end - sign);
                                    new_line_offset += end - sign;
                                    line_offset = end - line;
                                }
                            }
                        } else {
                            printf("-bbbb-\n");
                            break;
                        }
                    }
                    if (strstr(line, "</head>") != NULL) {
                        html_head_over = True;
                    }
                    if (need_change == False) {
                        memcpy(buff + offset, line, strlen(line));
                        offset += strlen(line);
                    } else {
                        memcpy(buff + offset, new_line, strlen(new_line));
                        offset += strlen(new_line);
                    }
                } else {
                    char *start = strstr(line, "src=");
                    int need_change = False;
                    if (start != NULL) {
                        char *end = strstr(line, ">");
                        if (end != NULL) {
                            char *sign = strrchr(line, '.');
                            char *name = sign;
                            if (sign != NULL) {
                                while ((*name) != '/' && (*name) != '=' && (*name) != '\"') {
                                    name--;
                                }
                                if ((*name) == '/') {
                                    need_change = True;
                                    strncpy(new_line, line, start - line);
                                    if (strnstr(start, "\"", sign - start) != NULL) {
                                        strncpy(new_line + strlen(new_line), "src=\"", 5);
                                    } else {
                                        strncpy(new_line + strlen(new_line), "src=", 4);
                                    }
                                    strncpy(new_line + strlen(new_line), fold_name, strlen(fold_name));
                                    strncpy(new_line + strlen(new_line), name, sign - name);
                                    strncpy(new_line + strlen(new_line), sign, strlen(sign));
                                }
                            }
                        }
                    }
                    if (need_change == False) {
                        memcpy(buff + offset, line, strlen(line));
                        offset += strlen(line);
                    } else {
                        memcpy(buff + offset, new_line, strlen(new_line));
                        offset += strlen(new_line);
                    }
                }
            }
            
            //write file
            struct stat stat_buff;
            if (stat(path, &stat_buff) == 0) {
                snprintf(path, MAX_NAME_LEN, "%d_%s", get_random_num(), file_name);
                printf("HAVE SAME NAME FILE!! rename=%s\n", path);
            }

            FILE *output = fopen(path, "w+");
            fwrite(buff, len+1000, 1, output);
            fclose(output);
            free(buff);
        }
        if (fileno(tmp_fd) != fileno(fd)) {
            fclose(tmp_fd);
        }
        printf("------------------\n");
    }
    
    fclose(fd);
    
    return;
}

int main()
{
    char dirPath[MAX_PATH_LEN] = "./";
    list_all_files(dirPath);

    int i = 0;
    for (i = 0; i < name_cnt; i++) {
        printf("\n--------FILE=%s-------\n", File_Names[i]);
        convert(File_Names[i]);
        remove_file(File_Names[i]);
    }
    return 0;
}
