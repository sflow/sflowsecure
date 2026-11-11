# sflowsecure
One-way UDP encryption tunnel to forward sFlow over an untrusted network.

The steps are:
* clone this repo
* make
* make install
* use a password generator to generate a random 32-bit ASCII private key.
* as root, edit the unit file /lib/systemd/system/sflowsecure.service to set the mode (sender or receiver), listen (socket) and forward (socket) options, and install the secret key.
* double-check to make sure the unit file is only accessible to root.
* schedule it to run now and on reboot with:
  ```
  sudo systemctl enable sflowsecure.service
  sudo systemctl daemon-reload
  sudo systemctl start sflowsecure
  ```
* if you are at the sender end,  point your sFlow feeds to the listen socket.
  
  
## Example sender unit file

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
