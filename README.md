# p2p_python_sockets_over_lan
P2P chat app secured by web-of-trust.

Run this command in bash to generate your public/private key pair. Use the password you enter to login to the app.

`ssh-keygen -t ed25519 -f key`

Make sure you allow incoming TCP connections on port 65432! You can do it like this:

`sudo ufw allow 65432/tcp`
