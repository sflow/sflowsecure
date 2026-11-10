# sflowsecure
One-way UDP encryption tunnel to forward sFlow over an untrusted network.

## Example sender unit file

```
[Unit]
Description=sFlow Secure
After=network.target nss-lookup.target

[Service]
Type=simple
ExecStart=/usr/sbin/sflowsecure -mode sender -listen 127.0.0.1:6343 -forward 10.100.100.117:56343
Environment="SFLOWSECURE_KEY=4TG7iMTYtNVTZ1uRxiv2wriRxLXY1HpG"
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
Environment="SFLOWSECURE_KEY=4TG7iMTYtNVTZ1uRxiv2wriRxLXY1HpG"
TimeoutStopSec=10

[Install]
WantedBy=multi-user.target
