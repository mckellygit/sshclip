/*
 * Copyright (c) 2000 Sean Walton and Macmillan Publishers.  Use may be in
 * whole or in part in accordance to the General Public License (GPL).
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
*/

#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <netdb.h>
#include <errno.h>
#include <resolv.h>
#include <signal.h>
#include <poll.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define CLIPBOARD_PORT 22222
#define SERVER_SOCK    "/dev/shm/sshclipserver.sock"

int use_tls = 0;

/*
 * on originating-host:
 *  start sshclipserver:
 *    sshclipserver [cert-file key-file] (it listens on 22222)
 *  connect to remote host 1.2.3.4:
 *    export LC_MONETARY=sshterm:22221:22222
 *    ssh -R22221:localhost:22222 1.2.3.4
 *
 * then on 1.2.3.4
 *   if LC_MONETARY=sshterm:22221:22222 then we can use:
 *     sshclip (it connects to localhost:22221 - which gets sent through tunnel to originating-host:22222)
 */

char *run_cmd_get_output(int *clen)
{
    char *buf = NULL;
    int buflen = 0;

    *clen = 0;

    // add --rmlastnl here ?

    FILE *fp = popen("myclip -o", "r");
    if (fp == NULL)
    {
        int err = errno;

        buf = (char *)malloc(10);
        if (buf == NULL)
        {
            fprintf(stderr, "Error running command %d and allocating return buffer\n", err);
            *clen = 0;
            return NULL;
        }

        fprintf(stderr, "Error running command %d\n", err);
        buf[0] = '\0';
        *clen = 1;
        return buf;
    }

    buflen = 1024*100;
    buf = (char *)realloc(NULL, buflen);
    if (buf == NULL)
    {
        pclose(fp);
        fprintf(stderr, "Error allocating return buffer\n");
        *clen = 0;
        return NULL;
    }

    int offset = 0;

    while (1)
    {
        if ((offset + 1024) >= buflen)
        {
            buflen *= 2;
            buf = (char *)realloc(buf, buflen);
            if (buf == NULL)
            {
                pclose(fp);
                fprintf(stderr, "Error re-allocating return buffer\n");
                *clen = 0;
                return NULL;
            }
        }
        int bytes = fread(&buf[offset], 1, 1024, fp);
        if (bytes <= 0)
            break;
        offset += bytes;
    }

    pclose(fp);

    buf[offset] = '\0';
    *clen = offset + 1;
    return buf;
}

int ServerCheck(int act_server_port)
{
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    // should not echo any error text ...

    sd = socket(PF_INET, SOCK_STREAM, 0);
    if (sd < 0)
    {
        return -1;
    }

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(act_server_port);

    if ( (host = gethostbyname("localhost")) == NULL )
    {
        return -1;
    }

    // addr.sin_addr.s_addr = *(long*)(host->h_addr);
    memcpy((char *)&addr.sin_addr.s_addr, host->h_addr_list[0], host->h_length);

    // hack to set connect time without needing NONBLOCK + poll ...

    struct timeval conntime;
    conntime.tv_sec  = 3;
    conntime.tv_usec = 0;
    setsockopt(sd, SOL_SOCKET, SO_SNDTIMEO, &conntime, sizeof(conntime));

    // -----------

    if (connect(sd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        close(sd);
        return -1;
    }

    close(sd);
    return 0;
}

int ServerEnd(int act_server_port)
{
    int sd;
    struct sockaddr_un ctrl_addr;

    // should not echo any error text ...

    sd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (sd < 0)
    {
        return -1;
    }

    bzero(&ctrl_addr, sizeof(ctrl_addr));
    ctrl_addr.sun_family = AF_UNIX;
    strcpy(ctrl_addr.sun_path, SERVER_SOCK);

    // hack to set connect time without needing NONBLOCK + poll ...

    struct timeval conntime;
    conntime.tv_sec  = 3;
    conntime.tv_usec = 0;
    setsockopt(sd, SOL_SOCKET, SO_SNDTIMEO, &conntime, sizeof(conntime));

    // -----------

    if (connect(sd, (struct sockaddr *)&ctrl_addr, sizeof(ctrl_addr)) != 0)
    {
        close(sd);
        return -1;
    }

    // send cmd to exit, but then do we need to know if we are tls or not ?

    char cmdstr[1000];
    strcpy(cmdstr, "stop");
    int srtn = write(sd, cmdstr, 5);
    if (srtn != 5)
    {
        close(sd);
        return -1;
    }

    close(sd);
    return 0;
}

int OpenListener(int port, int *sd, int *ctld)
{
    struct hostent *host;
    struct sockaddr_in addr;

    // should not echo any error text ...

    *sd = socket(PF_INET, SOCK_STREAM, 0);
    if (*sd < 0)
    {
        return -1;
    }

    int on = 1;
    setsockopt(*sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    // could set SO_REUSEADDR or not linger ...
    struct linger ling;
    ling.l_onoff = 1;
    ling.l_linger = 3;
    setsockopt(*sd, SOL_SOCKET, SO_LINGER, &ling, sizeof(ling));

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    // addr.sin_addr.s_addr = htonl(INADDR_ANY);

    // only accept connection from localhost ...

    // addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    // addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if ( (host = gethostbyname("localhost")) == NULL )
    {
        return -1;
    }

    // addr.sin_addr.s_addr = *(long*)(host->h_addr);
    memcpy((char *)&addr.sin_addr.s_addr, host->h_addr_list[0], host->h_length);

    if (bind(*sd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        return -1;
    }

    if (listen(*sd, 10) != 0)
    {
        return -1;
    }

    // -------------

    struct sockaddr_un ctrl_addr;

    *ctld = socket(PF_UNIX, SOCK_STREAM, 0);  // DATAGRAM ?
    if (*ctld < 0)
    {
        return -1;
    }

    struct linger cling;
    cling.l_onoff = 1;
    cling.l_linger = 3;
    setsockopt(*ctld, SOL_SOCKET, SO_LINGER, &cling, sizeof(cling));

    bzero(&ctrl_addr, sizeof(ctrl_addr));
    ctrl_addr.sun_family = AF_UNIX;
    strcpy(ctrl_addr.sun_path, SERVER_SOCK);
    unlink(ctrl_addr.sun_path);

    if (bind(*ctld, (struct sockaddr *)&ctrl_addr, sizeof(ctrl_addr)) != 0)
    {
        return -1;
    }

    if (listen(*ctld, 10) != 0)
    {
        return -1;
    }

    return 0;
}

SSL_CTX* InitServerCTX(void)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    SSL_library_init();

    OpenSSL_add_all_algorithms();

    SSL_load_error_strings();

    method = SSLv23_server_method();

    ctx = SSL_CTX_new(method);
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    return ctx;
}

int LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        return -1;
    }

    return 0;
}

int CheckCert(SSL* ssl)
{
    // TODO: should log errors to syslog ...

    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);
    if (cert == NULL)
    {
        // fprintf(stderr, "No client certificate\n");
        return -1;
    }

    printf("Client certificate:\n");

    line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);

    fprintf(stderr, "Subject: %s\n", line);

    free(line);

    line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);

    fprintf(stderr, "Issuer: %s\n", line);

    free(line);

    X509_free(cert);

    return 0;
}

void Servlet(SSL* ssl)
{
    // TODO: should log errors to syslog ...

    if (SSL_accept(ssl) == -1)
    {
        ERR_print_errors_fp(stderr);
        return;
    }
    else
    {
        // verify ?

        int srtn = CheckCert(ssl);
        if (srtn < 0)
        {
            // dont proceed if client cert not ok ...
            // return;
        }

        char cmdstr[1000];
        int bytes = SSL_read(ssl, cmdstr, 18);
        if (bytes == 0)
        {
            // assume some sort of port health check ...
            return;
        }

        if (bytes != 18)
        {
            fprintf(stderr, "Error recving length, %d != %u\n", bytes, 18);
            return;
        }

        // printf("cmdstr = <%s>\n", cmdstr);

        int myuid, myeuid;
        srtn = sscanf(cmdstr,"%8d:%8d", &myuid, &myeuid);
        if (srtn != 2)
        {
            fprintf(stderr, "Error invalid cmdstr format\n");
            return;
        }

        if ( ((uid_t)myuid != getuid()) || ((uid_t)myeuid != geteuid()) )
        {
            fprintf(stderr, "Error not valud client user/euser id\n");
            return;
        }

        // get clipboard data and send ...

        int blen = 0;
        char *buf = run_cmd_get_output(&blen);

        if (buf == NULL)
        {
            // client read will fail ...
            return;
        }

        int wlen = htonl(blen);
        srtn = SSL_write(ssl, &wlen, sizeof(wlen));
        if (srtn != sizeof(wlen))
        {
            fprintf(stderr, "Error writing initial len to socket %d\n", srtn);
            return;
        }

        srtn = SSL_write(ssl, buf, blen);
        if (srtn != blen)
        {
            fprintf(stderr, "Error writing data to socket %d != %d\n", srtn, blen);
            return;
        }

        free(buf);
    }

    return;
}

void Servlet2(int sock)
{
    // TODO: should log errors to syslog ...

    char cmdstr[1000];
    int bytes = read(sock, cmdstr, 18);
    if (bytes == 0)
    {
        // assume some sort of port health check ...
        return;
    }

    if (bytes != 18)
    {
        fprintf(stderr, "Error recving length, %d != %u\n", bytes, 18);
        return;
    }

    // printf("cmdstr = <%s>\n", cmdstr);

    int myuid, myeuid;
    int srtn = sscanf(cmdstr,"%8d:%8d", &myuid, &myeuid);
    if (srtn != 2)
    {
        fprintf(stderr, "Error invalid cmdstr format\n");
        return;
    }

    if ( ((uid_t)myuid != getuid()) || ((uid_t)myeuid != geteuid()) )
    {
        fprintf(stderr, "Error not valid client user/euser id\n");
        return;
    }

    // get clipboard data and send ...

    int blen = 0;
    char *buf = run_cmd_get_output(&blen);

    if (buf == NULL)
    {
        // client read will fail ...
        return;
    }

    int wlen = htonl(blen);
    srtn = write(sock, &wlen, sizeof(wlen));
    if (srtn != sizeof(wlen))
    {
        fprintf(stderr, "Error writing initial len to socket %d\n", srtn);
        return;
    }

    srtn = write(sock, buf, blen);
    if (srtn != blen)
    {
        fprintf(stderr, "Error writing data to socket %d != %d\n", srtn, blen);
        return;
    }

    free(buf);

    return;
}

// to create cert and key files needed to run this server:
// openssl genrsa -out privkey.pem 2048
// openssl req -new -sha256 -nodes -key privkey.pem -out cert.csr
// openssl x509 -req -days 365 -in cert.csr -signkey privkey.pem -out cert.crt
// rm -f cert.csr

SSL_CTX *ctx = NULL;
int sock, ctld;

void intr_hdl(int sig)
{
    close(sock);
    close(ctld);
    if (use_tls)
        SSL_CTX_free(ctx);
    unlink(SERVER_SOCK);
    exit(0);
}

int main(int argc, char *argv[])
{
    char *cert_file = NULL;
    char *priv_key = NULL;

    if (argc == 2)
    {
        if (strcmp(argv[1],"-c") == 0)
        {
            exit(ServerCheck(CLIPBOARD_PORT));
        }
        else if (strcmp(argv[1],"-x") == 0)
        {
            exit(ServerEnd(CLIPBOARD_PORT));
        }
        else
        {
            printf("Usage: %s [-c] | cert.crt privkey.pem\n", argv[0]);
            exit(1);
        }
    }
    else if (argc == 3)
    {
        cert_file = argv[1];
        priv_key = argv[2];
        use_tls = 1;
    }
    else if (argc != 1)
    {
        printf("Usage: %s [-c] | cert.crt privkey.pem\n", argv[0]);
        exit(1);
    }

    struct sigaction act;
    sigfillset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = &intr_hdl;
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGQUIT, &act, NULL);
    sigaction(SIGTERM, &act, NULL);

    if (use_tls)
    {
        ctx = InitServerCTX();
        if (ctx == NULL)
        {
            exit(1);
        }

        if (LoadCertificates(ctx, cert_file, priv_key) < 0)
        {
            SSL_CTX_free(ctx);
            exit(1);
        }
    }

    int srtn = OpenListener(CLIPBOARD_PORT, &sock, &ctld);
    if (srtn < 0)
    {
        perror("Error creating/binding/listening socket");
        if (use_tls)
            SSL_CTX_free(ctx);
        exit(1);
    }

    // TODO: from here on out should use syslog instead of stderr ...

    while (1)
    {
        struct sockaddr_in addr;
        struct sockaddr_un ctrl_addr;
        socklen_t len = sizeof(addr);
        socklen_t clen = sizeof(ctrl_addr);
        SSL *ssl = NULL;

        struct pollfd pfds[2];
	    memset(pfds, 0, sizeof(pfds));
	    pfds[0].fd = sock;
	    pfds[0].events = POLLIN;
	    pfds[1].fd = ctld;
	    pfds[1].events = POLLIN;

	    int rc = poll(pfds, 2, -1);
        if (rc <= 0)
            continue;

        if (pfds[1].revents & POLLIN)
        {
            int client = accept(ctld, (struct sockaddr *)&ctrl_addr, &clen);
            if (client >= 0)
            {
                char cmdstr[1000];
                int bytes = read(client, cmdstr, 5);
                if (bytes == 5)
                {
                    if (strncmp(cmdstr, "stop", 4) == 0)
                    {
                        if (use_tls)
                            SSL_free(ssl);

                        close(client);
                        break;
                    }
                }
                close(client);
            }
        }

        if (pfds[0].revents & POLLIN)
        {
            int client = accept(sock, (struct sockaddr *)&addr, &len);
            if (client >= 0)
            {
#if 0
                struct sockaddr_in a_addr;
                socklen_t a_len = sizeof(a_addr);
                int srtn = getpeername(client, (struct sockaddr *)&a_addr, &a_len);
                if (srtn)
                    continue;
                char ipstr[100];
                inet_ntop(AF_INET, &a_addr.sin_addr, ipstr, 99);
                fprintf(stderr, "client ip = \"%s\"\n", ipstr);
                // if not localhost then reject ? ... (already handled in bind/listen above)
#endif
                if (use_tls)
                {
                    ssl = SSL_new(ctx);
                    if (ssl == NULL)
                    {
                        close(client);
                        continue;
                    }
         
                    SSL_set_fd(ssl, client);
                }
         
                if (use_tls)
                    Servlet(ssl);
                else
                    Servlet2(client);
         
                if (use_tls)
                    SSL_free(ssl);
         
                close(client);
            }
        }
    }

    close(sock);
    close(ctld);

    if (use_tls)
        SSL_CTX_free(ctx);

    unlink(SERVER_SOCK);

    return 0;
}
