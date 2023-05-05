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
#include <resolv.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define CLIPBOARD_PORT 22222

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

// TODO: should we output errors to stderr ?

int OpenConnection(const char *hostname, int port)
{
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    sd = socket(PF_INET, SOCK_STREAM, 0);
    if (sd < 0)
    {
        perror("socket");
        return -1;
    }

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    // addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
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
        perror("connect");
        close(sd);
        return -1;
    }

    // reset to default (0) ...

    conntime.tv_sec  = 0;
    conntime.tv_usec = 0;
    setsockopt(sd, SOL_SOCKET, SO_SNDTIMEO, &conntime, sizeof(conntime));

    return sd;
}

SSL_CTX* InitCTX(void)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    SSL_library_init();

    OpenSSL_add_all_algorithms();

    SSL_load_error_strings();

    method = SSLv23_client_method();

    ctx = SSL_CTX_new(method);
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // load certificate and private key here ...

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

void ShowCerts(SSL* ssl)
{
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);
    if ( cert != NULL )
    {
        printf("server certificate:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No server certificate\n");
}

int main(int argc, char *argv[])
{
    char *hostname = "localhost";
    int server_port = CLIPBOARD_PORT;
    // int act_server_port = CLIPBOARD_PORT;
    SSL_CTX *ctx = NULL;
    int sock1;
    SSL *ssl = NULL;
    int bytes;
    char *cert_file = NULL;
    char *priv_key = NULL;

    char *ptr = getenv("LC_MONETARY");
    if (ptr != NULL)
    {
        if (strncmp(ptr, "sshterm:", 8) == 0)
        {
            char sptr[1001];
            strncpy(sptr, ptr, 1000);
            sptr[1000] = '\0';
         
            char *ptr0 = strtok(sptr, ":");
            if (ptr0 != NULL)
            {
                char *ptr1 = strtok(NULL, ":");
                if (ptr1 != NULL)
                {
                    // tunnel port ...
                    server_port = atoi(ptr1);
#if 0
                    char *ptr2 = strtok(NULL, ":");
                    if (ptr2 != NULL)
                    {
                        // actual server port if no tunnel ...
                        act_server_port = atoi(ptr2);
                    }
#endif
                }
            }
        }
    }

    if (argc == 3)
    {
        cert_file = argv[1];
        priv_key = argv[2];
        use_tls = 1;
    }

    if (use_tls)
    {
        ctx = InitCTX();
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

    sock1 = OpenConnection(hostname, server_port);
    if (sock1 < 0)
    {
        if (use_tls)
            SSL_CTX_free(ctx);
        exit(1);
    }

    // ---------------

    if (use_tls)
    {
        ssl = SSL_new(ctx);
        if (ssl == NULL)
        {
            SSL_CTX_free(ctx);
            fprintf(stderr, "Error creating new SSL structure\n");
            exit(1);
        }
    
        SSL_set_fd(ssl, sock1);
    
        if (SSL_connect(ssl) == -1)
        {
            ERR_print_errors_fp(stderr);
        }
        else
        {
            // verify ?
    
            // printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
    
            // ShowCerts(ssl);
    
            char cmdstr[1000];
            snprintf(cmdstr, 999, "%8d:%8d", getuid(), geteuid());
            int clen = (int)strlen(cmdstr);
            if (clen < 17)
            {
                for(;clen <= 17; clen++)
                    cmdstr[clen] = '\0';
            }
            // printf("cmdstr = <%s>\n", cmdstr);
            int srtn = SSL_write(ssl, cmdstr, 18);
            if (srtn != 18)
            {
                SSL_CTX_free(ctx);
                fprintf(stderr, "Error writing initial cmd to socket %d\n", srtn);
                exit(1);
            }
    
            int rlen0 = 0;
            bytes = SSL_read(ssl, &rlen0, sizeof(rlen0));
            if (bytes != sizeof(rlen0))
            {
                // if read fails then some permission or other problem ...
                SSL_CTX_free(ctx);
                // fprintf(stderr, "Error reading length, %d != %lu\n", bytes, sizeof(rlen0));
                exit(1);
            }
    
            // -------------
    
            int rlen = ntohl(rlen0);
    
            // if rlen == 0 then clipboard empty ...
    
            char *buf = (char *)malloc(rlen+100);
            if (buf == NULL)
            {
                SSL_CTX_free(ctx);
                fprintf(stderr,"Error allocating %d bytes for data\n", rlen);
                exit(1);
            }
    
            bytes = SSL_read(ssl, buf, rlen);
            if (bytes != rlen)
            {
                SSL_CTX_free(ctx);
                fprintf(stderr, "Error reading data, %d != %d\n", bytes, rlen);
                exit(1);
            }
    
            // fprintf(stderr, "rlen = %d\n", rlen);
    
            buf[rlen] = 0;
    
            printf("%s", buf);
            fflush(NULL);
    
            free(buf);
    
            SSL_free(ssl);
        }

    }
    else
    {
        char cmdstr[1000];
        snprintf(cmdstr, 999, "%8d:%8d", getuid(), geteuid());
        int clen = (int)strlen(cmdstr);
        if (clen < 17)
        {
            for(;clen <= 17; clen++)
                cmdstr[clen] = '\0';
        }
        // printf("cmdstr = <%s>\n", cmdstr);
        int srtn = write(sock1, cmdstr, 18);
        if (srtn != 18)
        {
            fprintf(stderr, "Error writing initial cmd to socket %d\n", srtn);
            exit(1);
        }
    
        int rlen0 = 0;
        bytes = read(sock1, &rlen0, sizeof(rlen0));
        if (bytes != sizeof(rlen0))
        {
            // if read fails then some permission or other problem ...
            // fprintf(stderr, "Error reading length, %d != %lu\n", bytes, sizeof(rlen0));
            exit(1);
        }
    
        // -------------
    
        int rlen = ntohl(rlen0);
    
        // if rlen == 0 then clipboard empty ...
    
        char *buf = (char *)malloc(rlen+100);
        if (buf == NULL)
        {
            fprintf(stderr,"Error allocating %d bytes for data\n", rlen);
            exit(1);
        }
    
        bytes = read(sock1, buf, rlen);
        if (bytes != rlen)
        {
            fprintf(stderr, "Error reading data, %d != %d\n", bytes, rlen);
            exit(1);
        }
    
        // fprintf(stderr, "rlen = %d\n", rlen);
    
        buf[rlen] = 0;
    
        printf("%s", buf);
        fflush(NULL);
    
        free(buf);
    }

    close(sock1);

    if (use_tls)
        SSL_CTX_free(ctx);

    return 0;
}
