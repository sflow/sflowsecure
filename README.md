# sflowsecure
One-way UDP encryption tunnel to forward sFlow over an untrusted network.

** Example unit file **

[Unit]
Description=sFlow Secure
After=network.target nss-lookup.target

[Service]
Type=simple
ExecStart=/usr/sbin/sflowsecure -mode sender -listen 127.0.0.1:56342 -forward 10.0.0.117:56343
Environment="SFLOWSECURE_KEY=4TG7iMTYtNVTZ1uRxiv2wriRxLXY1HpG"
TimeoutStopSec=10

[Install]
WantedBy=multi-user.target
