# sflowsecure Makefile

SFLOWSECURE=sflowsecure
INSTALL=install
USERADD=useradd
BINDIR ?=/usr/sbin
SYSTEMDDIR ?=/lib/systemd/system
CONFIGDIR ?=/etc/$(SFLOWSECURE)
ENVFILE=$(CONFIGDIR)/$(SFLOWSECURE).env

#########  hsflowd_containerd  #########

$(SFLOWSECURE): $(SFLOWSECURE).go
	echo "=== go mod init $(SFLOWSECURE) ==="; \
	go mod init $(SFLOWSECURE); \
	echo "=== go build $(SFLOWSECURE) ==="; \
	go build -ldflags="-s -w" $(SFLOWSECURE); \
	echo "=== compile $(SFLOWSECURE) done ==="

#########  install  #########

install: $(SFLOWSECURE)
	id -u $(SFLOWSECURE) >/dev/null 2>&1 || $(USERADD) -r -M -s /usr/sbin/nologin $(SFLOWSECURE)
	if [ ! -d "$(SYSTEMDDIR)" ]; then $(INSTALL) -d  $(SYSTEMDDIR); fi
	if [ ! -d "$(CONFIGDIR)" ]; then $(INSTALL) -d $(CONFIGDIR); fi
	if [ ! -d "$(BINDIR)" ]; then $(INSTALL) -d $(BINDIR); fi
	$(INSTALL) -m 755 $(SFLOWSECURE) $(BINDIR)
	$(INSTALL) -m 644 $(SFLOWSECURE).service $(SYSTEMDDIR)/$(SFLOWSECURE).service
	if [ ! -f "$(CONFIGDIR)/$(SFLOWSECURE).env" ]; then $(INSTALL) -m 600 $(SFLOWSECURE).env $(CONFIGDIR); fi

#########  schedule  #########

schedule:
	systemctl daemon-reload
	systemctl enable $(SFLOWSECURE)

unschedule:
	systemctl disable $(SFLOWSECURE)
	systemctl daemon-reload

#########  clean   #########

clean:
	rm -f $(SFLOWSECURE)

