#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <assert.h>

#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <vector>
// using namespace std;

// maximum size of message in bytes
const size_t k_max_msg = 4096;

enum
{
    STATE_REQ = 0, // mark connection to accept requests
    STATE_RES = 1, // mark connection to respond
    STATE_END = 2, // mark connection for deletion
};

struct Conn
{
    int fd = -1;
    uint32_t state = 0; // either STATE_REQ or STATE_RES
    // buffer for reading
    size_t rbuf_size = 0;
    uint8_t rbuf[4 + k_max_msg];
    // buffer for writing
    size_t wbuf_size = 0;
    size_t wbuf_sent = 0;
    uint8_t wbuf[4 + k_max_msg];
};

// Prints a given message to the standard error stream.
static void msg(const char *msg)
{
    // fprintf prints to any output stream, as opposed to printf which prints to standard output only
    fprintf(stderr, "%s\n", msg);
}

// Aborts from the program after printing the given message
static void die(const char *msg)
{
    int err = errno;
    fprintf(stderr, " [%d] %s\n", err, msg);
    abort();
}

// set a given fd to nonblocking so as to be compatible with an event loop
static void set_fd_to_nonblocking(int fd)
{
    errno = 0;
    int flags = fcntl(fd, F_GETFL, 0);
    if (errno)
    {
        die("fcntl error");
        return;
    }
    flags |= O_NONBLOCK;

    errno = 0;
    (void)fcntl(fd, F_SETFL, 0);
    if (errno)
    {
        die("fcntl error");
        return;
    }
}

// puts the new connection into the fd2conn vector of connections
static void conn_put(std::vector<Conn *> &fd2conn, struct Conn *conn)
{
    if (fd2conn.size() <= (size_t)conn->fd)
    {
        fd2conn.resize(conn->fd + 1);
    }
    // the fd value serves as the index or the key for the struct Conn object
    fd2conn[conn->fd] = conn;
}




static int32_t read_full(int fd, char *buf, size_t n)
{
    while (n > 0)
    {
        ssize_t rv = read(fd, buf, n);
        if (rv <= 0)
        {
            return -1; // error, or unexpected EOF
        }
        assert((size_t)rv <= n);
        n -= (size_t)rv;
        buf += rv;
    }
    return 0;
}

static int32_t write_all(int fd, const char *buf, size_t n)
{
    while (n > 0)
    {
        ssize_t rv = write(fd, buf, n);
        if (rv <= 0)
        {
            return -1; // error
        }
        assert((size_t)rv <= n);
        n -= (size_t)rv;
        buf += rv;
    }
    return 0;
}

static int32_t one_request(int connfd)
{
    char rbuf[4 + k_max_msg + 1];
    errno = 0;
    int32_t err = read_full(connfd, rbuf, 4);
    if (err)
    {
        if (errno == 0)
        {
            msg("EOF");
        }
        else
        {
            msg("read() error");
        }
        return err;
    }

    uint32_t len = 0;
    memcpy(&len, rbuf, 4);
    if (len > k_max_msg)
    {
        msg("too long");
        return -1;
    }

    // request body
    err = read_full(connfd, &rbuf[4], len);
    if (err)
    {
        msg("read() error");
        return err;
    }

    // do something
    rbuf[4 + len] = '\0';
    printf("client says: %s\n", &rbuf[4]);

    // reply using the same protocol
    const char reply[] = "world";
    char wbuf[4 + sizeof(reply)];
    len = (uint32_t)strlen(reply);
    memcpy(wbuf, &len, 4);
    memcpy(&wbuf[4], reply, len);
    return write_all(connfd, wbuf, 4 + len);
}

int main()
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        die("socket()");
    }
    int val = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = ntohs(1234);
    addr.sin_addr.s_addr = ntohl(0);

    int rv = bind(fd, (const sockaddr *)&addr, sizeof(addr));
    if (rv)
    {
        die("bind()");
    }

    // listen for a socket
    rv = listen(fd, SOMAXCONN);
    if (rv)
    {
        die("listen()");
    }

    while (true)
    {
        // accept the request
        struct sockaddr_in client_addr = {};
        socklen_t socklen = sizeof(client_addr);
        int connfd = accept(fd, (struct sockaddr *)&client_addr, &socklen);
        if (connfd < 0)
        {
            continue;
        }

        while (true)
        {
            int32_t err = one_request(connfd);
            if (err)
            {
                break;
            }
        }
        close(connfd);
    }
    return 0;
}
