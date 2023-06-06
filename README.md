bali
====

KISS containers for system services.
builds containers with Dockerfile, but distributes as signed tarball.

Downloads, verifies and runs tarballs, then cleans up everything on exit.

run has the exact same security isolation as running the process directly, i.e. none whatsoever.
Great for deploying your own system daemons, not so much for running random docker stuff from the internet.


### quickstart:

	echo from:alpine > Dockerfile
	bali build alpine.tar .
	bali run -e HELLO="im on a boat" -t ./alpine.tar -- /bin/busybox sh -c 'echo $HELLO'

### signed distribution


all tarballs are signed by default with identitykit
check your own id with

	bali id

verify a package is built by an id

	bali verify alpine.tar.gz cDFJ6F4W6XT2WGTLTJTDQAPE4GYXX2VVLSV43KWENB7W76FA57XAGZQA


verify before running stuff from the interwebs

	bali run -i cDFJ6F4W6XT2WGTLTJTDQAPE4GYXX2VVLSV43KWENB7W76FA57XAGZQA https://example.com/alpine.tar.gz


### installing from source:

install docker-buildx and golang, then:

	go build
	cp bali /usr/local/bin







### other things you should know about

you can extract a tarball and just run it with systemd too

	systemd-run --wait --pty --collect --service-type=exec -p RootDirectory=$PWD -- busybox httpd -vfp 8080


