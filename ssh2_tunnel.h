#pragma once

///
///
///

#include <iostream>
#include <thread>
#include <string>
#include <cstdlib>

#include <unistd.h>
#include <libssh2.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/select.h>
#include "common.h"

#ifndef INADDR_NONE
#define INADDR_NONE (in_addr_t)-1
#endif

using std::string;
using std::cout;
using std::endl;

class SSH2Tunnel {

    enum {
        AUTH_NONE = 0,
        AUTH_PASSWORD,
        AUTH_PUBLICKEY
    };

    public:
        SSH2Tunnel();
        SSH2Tunnel(const string &, const string &, const string &, const string &,
            const string &,const string &, const string &, const string &, int, int);
        ~SSH2Tunnel();
        SSH2Tunnel(const SSH2Tunnel &) = default;
        SSH2Tunnel(SSH2Tunnel &&) = default;
        SSH2Tunnel &operator=(const SSH2Tunnel &) = default;
        SSH2Tunnel &operator=(SSH2Tunnel &&) = default;
        void operator()();

    private:
        int                 m_rc;
        int                 m_i;
        int                 m_auth;
        int                 m_sock;
        struct hostent      *m_he;
        struct sockaddr_in  m_sin;
        const char          *m_fingerprint;
        char                *m_userauthlist;
        LIBSSH2_SESSION     *m_session;
        LIBSSH2_LISTENER    *m_listener;
        LIBSSH2_CHANNEL     *m_channel;

        string              m_server_ip;
        string              m_username;
        string              m_password;
        string              m_keyfile1;
        string              m_keyfile2;
        string              m_passphrase;
        string              m_remote_listenhost;
        string              m_local_destip;
        int                 m_remote_wantport;
        int                 m_remote_listenport;
        int                 m_local_destport;

        //void    copy_members_to_other_obj(const SSH2Tunnel &);
        void    shutdown_forward_tunnel(int);
        int     forward_tunnel(LIBSSH2_SESSION *, LIBSSH2_CHANNEL *);
};
