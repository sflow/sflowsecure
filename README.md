
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
3. Use a password generator to generate a random 32-bit ASCII private key.
4. As root, edit the unit file /lib/systemd/system/sflowsecure.service to set the mode (sender or receiver), listen socket and forward socket options, and install the secret key. The sender will encrypt using the key and the receiver will decrypt using the same key.
5. Schedule it to run with:
  ```
  sudo systemctl enable sflowsecure.service
  sudo systemctl daemon-reload
  sudo systemctl start sflowsecure
  ```
6. At the sender end, point your device sFlow feed(s) to the listen socket. The forward socket should point to the remote receiver, but _not_ to the standard 6343 port (we used 56343 in the example below).
7. Ensure that firewalls on the path will allow the traffic, including the software-firewall at the receiver.
8. At the receiver end, set listen to that port (e.g. 0.0.0.0:56343) and forward to the local sFlow collector.
  
  
### Example sender unit file

```
[Unit]
Description=sFlow Secure
After=network.target nss-lookup.target

[Service]
Type=simple
ExecStart=/usr/sbin/sflowsecure -mode sender -listen 127.0.0.1:6343 -forward 10.100.100.117:56343
Environment="SFLOWSECURE_KEY=<put your randomly-generated 32 character secret key string here>"
TimeoutStopSec=10

[Install]
WantedBy=multi-user.target
```
## Example receiver unit file
```
[Unit]
Description=sFlow Secure
After=network.target nss-lookup.target

[Service]
Type=simple
ExecStart=/usr/sbin/sflowsecure -mode receiver -listen 0.0.0.0:56343 -forward 127.0.0.1:6343
Environment="SFLOWSECURE_KEY=<put the exact same secret key string here>"
TimeoutStopSec=10

[Install]
WantedBy=multi-user.target
