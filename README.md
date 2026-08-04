# p2p_lan
P2P chat app written in Python and secured by web-of-trust.

## Installation
First, clone the repository

`git clone https://github.com/coolcodercat464/p2p_lan`

Then, run this command in bash to generate your public/private key pair. Use the password you enter to login to the app.

`ssh-keygen -t ed25519 -f key`

Make sure you allow incoming TCP connections on port 65432! You can do it like this:

`sudo ufw allow 65432/tcp`

Create a python virtual environment with

`python -m venv .`

And install the pip dependencies with

`pip install -r pip_requirements.txt`

Edit `connections.xml` to include the IP addresses and public keys of the devices in your LAN.
