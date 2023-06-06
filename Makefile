VERSION = $(shell git describe --tags --always --dirty)

bali: .PHONY

	go build .

deb: bali
	fpm \
		-f \
		-s dir -t deb \
		-p bali-$(VERSION)-amd64.deb \
		--name bali \
		--license APACHE2 \
		--version $(VERSION) \
		--architecture amd64 \
		--description "KISS containers for system services" \
		--url "https://github.com/kraudcloud/bali" \
		--maintainer "Arvid E. Picciani <aep@exys.org>" \
		bali=/usr/bin/bali






.PHONY:
