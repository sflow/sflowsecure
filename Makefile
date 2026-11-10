# This software is distributed under the following license:
# http://sflow.net/license.html

SFLOWSECURE=sflowsecure
INSTALL=install
BINDIR     ?= /usr/sbin
SYSTEMDDIR ?= /lib/systemd/system
SYSTEMD_D=$(SYSTEMDDIR)
BIN_D=$(BINDIR)

#########  hsflowd_containerd  #########

$(SFLOWSECURE): $(SFLOWSECURE).go
	echo "=== go mod init $(SFLOWSECURE) ==="; \
	go mod init $(SFLOWSECURE); \
	echo "=== go build $(SFLOWSECURE) ==="; \
	go build -ldflags="-s -w" $(SFLOWSECURE); \
	echo "=== compile $(SFLOWSECURE) done ==="

#########  install  #########

install: $(SFLOWSECURE)
	$(INSTALL) -d $(SYSTEMD_D)
	$(INSTALL) -m 644 $(SFLOWSECURE).service $(SYSTEMD_D)/$(SFLOWSECURE).service
	$(INSTALL) -m 700 $(SFLOWSECURE) $(BIN_D)

#########  schedule  #########

schedule:
	systemctl daemon-reload
	systemctl enable $(SFLOWSECURE)

#########  clean   #########

clean: 
	rm -f $(SFLOWSECURE)

