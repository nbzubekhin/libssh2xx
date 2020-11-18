#include "ssh2_tunnel.h"

SSH2Tunnel::SSH2Tunnel() {
}

SSH2Tunnel::SSH2Tunnel(const string &server_ip, const string &username,
        const string &password, const string &keyfile1, const string &keyfile2,
        const string &passphrase, const string &remote_listenhost,
        const string &local_destip, int remote_wantport, int local_destport) {
    this->m_server_ip = server_ip;
    this->m_username = username;
    this->m_password = password;
    this->m_keyfile1 = keyfile1;
    this->m_keyfile2 = keyfile2;
    this->m_passphrase = passphrase;
    this->m_remote_listenhost = remote_listenhost;
    this->m_local_destip = local_destip;
    this->m_remote_wantport = remote_wantport;
    this->m_local_destport = local_destport;
}

SSH2Tunnel::~SSH2Tunnel() {
    fprintf(stdout, "Call ~SSH2Tunnel()\n");

    if (m_channel) {
        while(libssh2_channel_close(m_channel) == LIBSSH2_ERROR_EAGAIN);
    }

    if (m_listener) {
        libssh2_channel_forward_cancel(m_listener);
    }

    if (m_session) {
        libssh2_session_disconnect(m_session, "Normal Shutdown, Thank you for playing");
        libssh2_session_free(m_session);
    }

    /// We must call the function libssh2_channel_free() at the end
    if (m_channel) {
        libssh2_channel_free(m_channel);
    }

    close(m_sock);
    libssh2_exit();
}

//void SSH2Tunnel::copy_members_to_other_obj(const SSH2Tunnel &obj) {
//    this->m_rc = obj.m_rc;
//    this->m_i = obj.m_rc;
//    this->m_auth = obj.m_auth;
//    this->m_sock = obj.m_sock;
//    this->m_he = obj.m_he;
//    this->m_sin = obj.m_sin;
//    this->m_fingerprint = obj.m_fingerprint;
//    this->m_userauthlist = obj.m_userauthlist;
//    this->m_session = obj.m_session;
//    this->m_listener = obj.m_listener;
//    this->m_channel = obj.m_channel;
//    this->m_server_ip = obj.m_server_ip;
//    this->m_username = obj.m_username;
//    this->m_password = obj.m_password;
//    this->m_keyfile1 = obj.m_keyfile1;
//    this->m_keyfile2 = obj.m_keyfile2;
//    this->m_passphrase = obj.m_passphrase;
//    this->m_remote_listenhost = obj.m_remote_listenhost;
//    this->m_local_destip = obj.m_local_destip;
//    this->m_remote_wantport = obj.m_remote_wantport;
//    this->m_remote_listenport = obj.m_remote_listenport;
//    this->m_local_destport = obj.m_local_destport;
//}

//SSH2Tunnel::SSH2Tunnel(const SSH2Tunnel &other_obj) {
//    this->copy_members_to_other_obj(other_obj);
//}

//SSH2Tunnel &SSH2Tunnel::operator=(const SSH2Tunnel &other_obj) {
//    if (this != &other_obj) {
//        this->copy_members_to_other_obj(other_obj);
//    }
//    return *this;
//}

void SSH2Tunnel::shutdown_forward_tunnel(int sock) {
    close(sock);
    /// Setting the session back to blocking IO
    libssh2_session_set_blocking(m_session, 1);
}

int SSH2Tunnel::forward_tunnel(LIBSSH2_SESSION *session, LIBSSH2_CHANNEL *channel) {

    int i, rc = 0;
    struct sockaddr_in sin;
    fd_set fds;
    struct timeval tv;
    ssize_t len, wr;
    char buf[16384];
    int forwardsock = -1;

    fprintf(stdout,
        "Accepted remote connection. Connecting to local server %s:%d\n",
        m_local_destip.c_str(), m_local_destport);
    forwardsock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (forwardsock == -1) {
        fprintf(stderr, "Error opening socket\n");
        this->shutdown_forward_tunnel(forwardsock);
        return rc;
    }

    sin.sin_family = AF_INET;
    sin.sin_port = htons(m_local_destport);
    if ((sin.sin_addr.s_addr = inet_addr(m_local_destip.c_str())) == INADDR_NONE) {
        fprintf(stderr, "Invalid local IP address\n");
        this->shutdown_forward_tunnel(forwardsock);
        return rc;
    }

    if (connect(forwardsock, (struct sockaddr *)&sin, sizeof(struct sockaddr_in)) == -1) {
        fprintf(stderr, "Failed to connect!\n");
        this->shutdown_forward_tunnel(forwardsock);
        return rc;
    }

    fprintf(stdout, "Forwarding connection from remote %s:%d to local %s:%d\n",
        m_remote_listenhost.c_str(), m_remote_listenport, 
        m_local_destip.c_str(), m_local_destport);

    /* Setting session to non-blocking IO */
    libssh2_session_set_blocking(m_session, 0);

    for ( ; ; ) {
        FD_ZERO(&fds);
        FD_SET(forwardsock, &fds);
        tv.tv_sec = 0;
        tv.tv_usec = 100000;
        rc = select(forwardsock + 1, &fds, NULL, NULL, &tv);
        if (rc == -1) {
            fprintf(stderr, "Socket not ready!\n");
            this->shutdown_forward_tunnel(forwardsock);
            return rc;
        }
        if (rc && FD_ISSET(forwardsock, &fds)) {
            len = recv(forwardsock, buf, sizeof(buf), 0);
            if (len < 0) {
                fprintf(stderr, "Error reading from the forwardsock!\n");
                this->shutdown_forward_tunnel(forwardsock);
                return rc;
            } else if (len == 0) {
                fprintf(stderr, "The local server at %s:%d disconnected!\n",
                    m_local_destip.c_str(), m_local_destport);
                this->shutdown_forward_tunnel(forwardsock);
                return rc;
            }
            wr = 0;
            do {
                i = libssh2_channel_write(m_channel, buf, len);
                if (i < 0) {
                    fprintf(stderr, "Error writing on the SSH channel: %d\n", i);
                    this->shutdown_forward_tunnel(forwardsock);
                    return rc;
                }
                wr += i;
            } while (i > 0 && wr < len);
        }
        for ( ; ; ) {
            len = libssh2_channel_read(m_channel, buf, sizeof(buf));
            if (len == LIBSSH2_ERROR_EAGAIN) {
                break;
            } else if (len < 0) {
                fprintf(stderr, "Error reading from the SSH channel: %d\n", (int)len);
                this->shutdown_forward_tunnel(forwardsock);
                return rc;
            }
            wr = 0;
            while (wr < len) {
                i = send(forwardsock, buf + wr, len - wr, 0);
                if (i <= 0) {
                    fprintf(stderr, "Error writing on the forwardsock!\n");
                    this->shutdown_forward_tunnel(forwardsock);
                    return rc;
                }
                wr += i;
            }
            if (libssh2_channel_eof(m_channel)) {
                fprintf(stderr, "The remote client at %s:%d disconnected!\n",
                    m_remote_listenhost.c_str(), m_remote_listenport);
                this->shutdown_forward_tunnel(forwardsock);
                return rc;
            }
        }
    }

    return rc;
}

void SSH2Tunnel::operator()() {

    int err = 0;

    m_rc = libssh2_init(0);
    if (m_rc != 0) {
        fprintf (stderr, "libssh2 initialization failed (%d)\n", m_rc);
        return;
    }

    /// Connect to SSH server
    m_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_sock == -1) {
        fprintf(stderr, "Error opening socket\n");
        return;
    }

    m_sin.sin_family = AF_INET;
    /// Will try resolve host
    if ((m_he = gethostbyname(m_server_ip.c_str())) == NULL) {
        if (INADDR_NONE == (m_sin.sin_addr.s_addr = inet_addr(m_server_ip.c_str()))) {
            fprintf(stderr, "Invalid remote IP address\n");
            return;
        }
    } else {
        /// Copy the first network address to sockaddr_in structure
        memcpy(&m_sin.sin_addr, m_he->h_addr_list[0], m_he->h_length);
    }

    m_sin.sin_port = htons(22); /* SSH port */
    if (connect(m_sock, (struct sockaddr *)(&m_sin), sizeof(struct sockaddr_in)) != 0) {
        fprintf(stderr, "Failed to connect!\n");
        return;
    }

    /// Create a session instance
    m_session = libssh2_session_init();
    if (!m_session) {
        fprintf(stderr, "Could not initialize the SSH session!\n");
        return;
    }

    /// This will trade welcome banners, exchange keys,
    /// and setup crypto, compression, and MAC layers
    m_rc = libssh2_session_handshake(m_session, m_sock);
    if (m_rc) {
        fprintf(stderr, "Error when starting up SSH session: %d\n", m_rc);
        return;
    }

    /// At this point we havn't yet authenticated.  The first thing to do
    /// is check the hostkey's fingerprint against our known hosts Your app
    /// may have it hard coded, may go to a file, may present it to the
    /// user, that's your call
    m_fingerprint = libssh2_hostkey_hash(m_session, LIBSSH2_HOSTKEY_HASH_SHA1);
    fprintf(stdout, "Fingerprint: ");
    for (m_i = 0; m_i < 20; m_i++)
        fprintf(stdout, "%02X:", (unsigned char)m_fingerprint[m_i]);
    fprintf(stdout, "\n");

    /// Check what authentication methods are available
    m_userauthlist = libssh2_userauth_list(m_session, m_username.c_str(), m_username.length());
    fprintf(stderr, "Authentication methods: %s\n", m_userauthlist);
    if (strstr(m_userauthlist, "password")) {
        m_auth |= AUTH_PASSWORD;
    }
    if (strstr(m_userauthlist, "publickey")) {
        m_auth |= AUTH_PUBLICKEY;
    }

    if ((m_auth & AUTH_PASSWORD) && (strlen(m_password.c_str()) != 0)) {
        /// We could authenticate via password
        while ((err =
                    libssh2_userauth_password(m_session, 
                                                m_username.c_str(), 
                                                m_password.c_str())) == LIBSSH2_ERROR_EAGAIN);
        if (err) {
            fprintf(stderr, "Authentication by password failed\n");
        } else {
            fprintf(stdout, "Authentication by password succeeded\n");
        }
    } else if (m_auth & AUTH_PUBLICKEY) {
        /// We could authenticate via publickey
        while ((err =
                    libssh2_userauth_publickey_fromfile(m_session, 
                        m_username.c_str(),
                        m_keyfile1.c_str(),
                        m_keyfile2.c_str(),
                        m_passphrase.c_str()) == LIBSSH2_ERROR_EAGAIN)
        );
        if (err) {
            fprintf(stderr, "Authentication by public key failed\n");
        } else {
            fprintf(stdout, "Authentication by public key succeeded.\n");
        }
    } else {
        fprintf(stderr, "No supported authentication methods found!\n");
        return;
    }

    if (err == LIBSSH2_ERROR_ALLOC) {
        fprintf(stderr, "LIBSSH2: An internal memory allocation call failed\n");
        return;
    } else if (err == LIBSSH2_ERROR_SOCKET_SEND) {
        fprintf(stderr, "LIBSSH2: Unable to send data on socket\n");
        return;
    } else if (err == LIBSSH2_ERROR_SOCKET_TIMEOUT) {
        fprintf(stderr, "LIBSSH2: Error socket timeout\n");
        return;
    } else if (err == LIBSSH2_ERROR_PUBLICKEY_UNVERIFIED) {
        fprintf(stderr, "LIBSSH2: The username/public key combination was invalid\n");
        return;
    } else if (err == LIBSSH2_ERROR_AUTHENTICATION_FAILED) {
        fprintf(stderr, "LIBSSH2: Authentication using the supplied public key was not accepted\n");
        return;
    } else if (err == LIBSSH2_ERROR_PASSWORD_EXPIRED) {
        fprintf(stderr, "LIBSSH2: Error password expired\n");
        return;
    } else if (err != 0) {
        fprintf(stderr, "LIBSSH2: Authentication failed, error_code: %d\n", err);
        return;
    }

    fprintf(stdout, "Asking server to listen on remote %s:%d\n",
        m_remote_listenhost.c_str(), m_remote_wantport);

    m_listener = libssh2_channel_forward_listen_ex(m_session, m_remote_listenhost.c_str(),
                                                    m_remote_wantport, &m_remote_listenport, 2);
    if (!m_listener) {
        fprintf(stderr, "Could not start the tcpip-forward listener!\n"
                "(Note that this can be a problem at the server!"
                " Please review the server logs.)\n");
        return;
    }

    fprintf(stdout, "Server is listening on %s:%d\n", m_remote_listenhost.c_str(), m_remote_listenport);

    for ( ; ; ) {
        fprintf(stdout, "Waiting for remote connection\n");
        m_channel = libssh2_channel_forward_accept(m_listener);
        if (!m_channel) {
            fprintf(stderr, "Could not accept connection!\n"
                    "(Note that this can be a problem at the server!"
                    " Please review the server logs.)\n");
            return;
        }

        forward_tunnel(m_session, m_channel);

        libssh2_channel_free(m_channel);
    }
}
