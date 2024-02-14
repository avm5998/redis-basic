#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <string>
#include <vector>
#include <map>

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
    // current size of the read buffer
    size_t rbuf_size = 0;
    // buffer for reading
    uint8_t rbuf[4 + k_max_msg];
    // current size of the write buffer
    size_t wbuf_size = 0;
    size_t wbuf_sent = 0;
    // buffer for writing
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

// puts the new connection into the fd2conn vector of connections, mapped by fd keys
static void conn_put(std::vector<Conn *> &fd2conn, struct Conn *conn)
{
    if (fd2conn.size() <= (size_t)conn->fd)
    {
        fd2conn.resize(conn->fd + 1);
    }
    // the fd value serves as the index or the key for the struct Conn object
    fd2conn[conn->fd] = conn;
}

// accepts a new connection, sets it to nonblocking and creates a Conn object for it
static int32_t accept_new_conn(std::vector<Conn *> &fd2conn, int fd)
{

    // accept
    struct sockaddr_in client_addr = {};
    socklen_t socklen = sizeof(client_addr);
    int connfd = accept(fd, (struct sockaddr *)&client_addr, &socklen);
    if (connfd < 0)
    {
        msg("accept() error");
        return -1;
    }

    // set the new connection to nonblocking
    set_fd_to_nonblocking(connfd);

    // create the struct Conn
    struct Conn *conn = (struct Conn *)malloc(sizeof(struct Conn));
    if (!conn)
    {
        close(connfd);
        return -1;
    }
    // conn is a pointer to a struct here, so we use the -> operator
    conn->fd = connfd;
    conn->state = STATE_REQ;
    conn->rbuf_size = 0;
    conn->wbuf_size = 0;
    conn->wbuf_sent = 0;
    conn_put(fd2conn, conn);
    return 0;
}

// definitions for functions that will be used later
static void state_req(Conn *conn);
static void state_res(Conn *conn);

static int32_t parse_req(const uint8_t *data,size_t len,std::vector<std::string>&out) {
    if(len<4) {
        return -1;
    }
    uint32_t n=0;
    memcpy(&n,&data[0],4);
    // n is the number of strings, nstr
    if(n>k_max_msg) {
        return -1;
    }
    size_t pos=4;
    while(n--) {
        if(pos+4 >len) {
            // breaking condition coz this means there is no string here after its length is obtained
            return -1;
        }
        uint32_t sz=0;
        memcpy(&sz,&data[pos],4);
        // index [pos,pos+3] stores the length of the string, which we store in sz
        if(pos+4+sz>len &&n>0) {
            return -1;
        }
        //sz is the length of the string
        out.push_back(std::string((char *)&data[pos+4],sz));
        pos+=4+sz;
    }

    if(pos!=len) {
        return -1;
        // our request has some extra input
    }
    return 0;
}

enum {
    RES_OK = 0,
    RES_ERR = 1,
    RES_NX = 2,
};


static std::map<std::string,std::string> g_map;

static uint32_t do_get(const std::vector<std::string> &cmd, uint8_t *res, uint32_t *reslen) {
    if(!g_map.count(cmd[1])) {
        return RES_NX;
    }
    std::string &val= g_map[cmd[1]];
    assert(val.size()<=k_max_msg);
    // we use val.data() since using memcpy on val, a string is not safe.
    // we copy the value into the response
    memcpy(res,val.data(),val.size());
    *reslen=(uint32_t)val.size();
    // we return a status code that says ok
    return RES_OK;
}
static uint32_t do_set(const std::vector<std::string> &cmd, uint8_t *res, uint32_t *reslen) {
    (void)res;
    (void)reslen;
    g_map[cmd[1]]=cmd[2];
    return RES_OK;
}
static uint32_t do_del(const std::vector<std::string> &cmd, uint8_t *res, uint32_t *reslen) {
    // used to explicitly indicate to the compiler that the variables res and reslen are intentionally not used within the function. 
    // This technique is often employed to suppress compiler warnings about unused variables.
    (void)res;
    (void)reslen;
    g_map.erase(cmd[1]);
    return RES_OK;
}

// const ensures that the function doesnt modify the parameters passed to it
static bool cmd_is(const std::string &word,const char *cmd) {
    return 0 == strcasecmp(word.c_str(),cmd);
}


static int32_t do_request(const uint8_t *req,uint32_t reqlen,uint32_t *rescode,uint8_t *res,uint32_t *reslen) {
    std::vector<std::string>cmd;
    if(0!=parse_req(req,reqlen,cmd)) {
        msg("bad req");
        return -1;
    }

    if(cmd.size()==2&& cmd_is(cmd[0],"get")) {
        *rescode=do_get(cmd,res,reslen);
    } else if(cmd.size()==2&&cmd_is(cmd[0],"del")) {
        *rescode=do_del(cmd,res,reslen);
    } else if(cmd.size()==3&&cmd_is(cmd[0],"set")) {
        *rescode=do_set(cmd,res,reslen);
    } else {
        // cmd is not recognized
        *rescode=RES_ERR;
        const char *msg="Unknown cmd";
        strcpy((char *)res,msg);
        *reslen=strlen(msg);
    }
    return 0;

}

static bool try_one_request(Conn *conn)
{
    // try and parse a request from the buffer
    if (conn->rbuf_size < 4)
    {
        // not enough data in the buffer, retry in the next iteration
        return false;
    }
    uint32_t len = 0;
    memcpy(&len, &conn->rbuf[0], 4);
    //this len here is the number of strings in the command

    // 4 coz we need 4 bytes, which store the length of the message in them
    if (len > k_max_msg)
    {
        msg("too long");
        conn->state = STATE_END;
        return false;
        // we got a msg thats too long, so we are removing the client
        // this behaviour can be changed
    }
    if (4 + len > conn->rbuf_size)
    {
        // we have not got the entire message in the read buffer yet, only a part of it
        // so we defer to process it until we get it all
        return false;
    }

    uint32_t rescode = 0;
    uint32_t wlen=0;
    int32_t err=do_request(&conn->rbuf[4],len,&rescode, &conn->wbuf[4+4],&wlen);

    if(err) {
        conn->state=STATE_END;
        return false;
    }
    wlen+=4;
    // first 4 bytes of wbuf are for the length of the succeeding message- both rescode and data
    memcpy(&conn->wbuf[0],&wlen,4);
    // next 4 bytes are for the rescode
    memcpy(&conn->wbuf[4],&rescode,4);
    conn->wbuf_size=4+wlen;

    // remove the request from the buffer.
    // note: frequent memmove is inefficient.
    // note: need better handling for production code.

    size_t remain=conn->rbuf_size - len -4;
    if(remain) {
        memmove(conn->rbuf,&conn->rbuf[len+4],remain);
    }
    conn->rbuf_size=remain;

    //change state
    conn->state=STATE_RES;
    state_res(conn);

    return (conn->state==STATE_REQ);

}

static bool try_fill_buffer(Conn *conn)
{
    // try to fill the buffer
    assert(conn->rbuf_size < sizeof(conn->rbuf));
    ssize_t rv = 0;
    do
    {
        size_t cap = sizeof(conn->rbuf) - conn->rbuf_size;
        rv = read(conn->fd, &conn->rbuf[conn->rbuf_size], cap);
    } while (rv < 0 && errno == EINTR);

    if (rv < 0 && errno == EAGAIN)
    {
        // got EAGAIN, stop. come out of the loop
        return false;
    }
    if (rv < 0)
    {
        msg("read() error");
        conn->state = STATE_END;
        return false;
    }
    if (rv == 0)
    {
        if (conn->rbuf_size > 0)
        {
            msg("unexpected EOF");
        }
        else
        {
            msg("EOF");
        }
        conn->state = STATE_END;
        return false;
    }

    conn->rbuf_size += (size_t)rv;
    assert(conn->rbuf_size <= sizeof(conn->rbuf));

    // to enable pipelining, clients can send multiple requests one after the other
    while (try_one_request(conn))
    {
    }
    return (conn->state == STATE_REQ);
}

static void state_req(Conn *conn)
{
    while (try_fill_buffer(conn))
    {
    }
}

static bool try_flush_buffer(Conn *conn)
{
    ssize_t rv = 0;
    do
    {
        // loop ends when write suceeds, indicating that all data has been written
        size_t remain = conn->wbuf_size - conn->wbuf_sent;
        rv = write(conn->fd, &conn->wbuf[conn->wbuf_sent], remain);
    } while (rv < 0 && errno == EINTR);
    if (rv < 0 && errno == EAGAIN)
    {
        return false;
    }
    if (rv < 0)
    {
        msg("write() error");
        conn->state = STATE_END;
        return false;
    }
    conn->wbuf_sent += (size_t)rv;
    assert(conn->wbuf_sent <= conn->wbuf_size);
    if (conn->wbuf_sent == conn->wbuf_size)
    {
        // response fully sent, change state back
        conn->state = STATE_REQ;
        conn->wbuf_sent = 0;
        conn->wbuf_size = 0;
        return false;
    }
    // still have some data, try again
    return true;
}

static void state_res(Conn *conn)
{
    while (try_flush_buffer(conn))
    {
    }
}

// helper function that calls the correct function depending on the connection state
static void connection_io(Conn *conn)
{
    if (conn->state == STATE_REQ)
    {
        state_req(conn);
    }
    else if (conn->state == STATE_RES)
    {
        state_res(conn);
    }
    else
    {
        assert(0);
        // unexpected
    }
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

    // bind
    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = ntohs(1234);
    addr.sin_addr.s_addr = ntohl(0); // wildcard address 0.0.0.0

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

    // map of all client connections, keyed by fd
    std::vector<Conn *> fd2conn;

    // set listening fd to nonblocking mode
    set_fd_to_nonblocking(fd);

    // event loop
    std::vector<struct pollfd> poll_args;
    while (true)
    {
        // prepare the arguments of the poll()
        poll_args.clear();
        // listening fd is put in first position for our convenience
        struct pollfd pfd = {fd, POLLIN, 0};
        poll_args.push_back(pfd);
        // connection fds
        for (Conn *conn : fd2conn)
        {
            if (!conn)
                continue;
            struct pollfd pfd = {};
            pfd.fd = conn->fd;
            pfd.events = (conn->state == STATE_REQ) ? POLLIN : POLLOUT;
            pfd.events = pfd.events | POLLERR;
            poll_args.push_back(pfd);
        }

        // poll for active fds
        // the timeout argument doesn't matter much here
        // this line is the only blocking line
        int rv = poll(poll_args.data(), (nfds_t)poll_args.size(), 1000);
        if (rv < 0)
        {
            die("poll");
        }

        // process active connections

        // start from index 1 as index 0 is the listening socket
        for (size_t i = 1; i < poll_args.size(); ++i)
        {
            // some event did occur on that socket
            if (poll_args[i].revents)
            {
                Conn *conn = fd2conn[poll_args[i].fd];
                connection_io(conn);

                // socket is marked for deletion
                if (conn->state == STATE_END)
                {
                    // client closed normally, or something bad happened.
                    // destroy this connection
                    fd2conn[conn->fd] = NULL;
                    (void)close(conn->fd);
                    free(conn);
                }
            }
        }

        // try to accept a new connection if the listening fd is active
        if (poll_args[0].revents)
        {
            (void)accept_new_conn(fd2conn, fd);
        }
    }
    return 0;
}
