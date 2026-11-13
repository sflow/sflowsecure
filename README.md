
# sflowsecure

One-way UDP encryption tunnel: forward sFlow over an untrusted network.

The steps are:
1. Clone this repo
2. Compile with:
```
cd sflowsecure
make
sudo make install
```
3. Use a password generator to generate a random 64-character-hex secret key (e.g. `openssl rand -hex 32`).
4. As root, edit the config file /etc/sflowsecure/sflowsecure.env to install the secret key and set the mode (sender or receiver), listen (socket), and forward (socket) options. The sender(s) will encrypt using the key and the receiver will decrypt using the same key.
5. Schedule it to run with:
  ```
  sudo systemctl enable sflowsecure.service
  sudo systemctl daemon-reload
  sudo systemctl start sflowsecure
  ```
6. At the sender end, point your device sFlow feed(s) to the listen socket. The forward socket should point to the remote receiver, but _not_ to the standard 6343 port (we used 56343 in the example below).
7. Ensure that firewalls on the path will allow the traffic, including the software-firewall at the receiver.
8. At the receiver end, set listen to that port (e.g. 0.0.0.0:56343) and forward to the local sFlow collector.
  
  
### Example sender sflowsecure.env file (should only be readable by root)

```
SFLOWSECURE_KEY=<insert random 64-character-hex secret key here>
SFLOWSECURE_MODE=sender
SFLOWSECURE_LISTEN=0.0.0.0:6343
SFLOWSECURE_FORWARD=10.100.100.1:56343
```

### Example receiver sflowsecure.env file (should only be readable by root)

```
SFLOWSECURE_KEY=<same hex key as above>
SFLOWSECURE_MODE=receiver
SFLOWSECURE_LISTEN=0.0.0.0:56343
SFLOWSECURE_FORWARD=127.0.0.1:6343
```
