#include <iostream>
#include <thread>
#include <cstdlib>
#include "ssh2_tunnel.h"

using std::thread;
using std::cout;
using std::endl;

int main(int argc, char *argv[]) {

    SSH2Tunnel ssh2_tunnel{
        "peer",                     // Server IP (Server in a private Network where runs PostgreSQL) 128.221.255.116
        "root",                     // usrename 
        "",                         // password
        "/root/.ssh/id_rsa.pub",    // public key 
        "/root/.ssh/id_rsa",        // private key
        "",                         // passphrase
        "peer",                     // remote_listenhost 
        "127.0.0.1",                // local_destip
        4000,                       // remote_wantport
        5432                        // local_destport
    };

    /// This will call move constructor
    SSH2Tunnel ssh2_tunnel_new(std::move(ssh2_tunnel));

    thread thrd_revers_ssh_tunnel(std::ref(ssh2_tunnel_new));
    thrd_revers_ssh_tunnel.detach();

    cout << "Start listen and wait 10 sec..." << endl;
    sleep(600);

    return EXIT_SUCCESS;
}
