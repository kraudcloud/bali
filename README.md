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
	sudo bali run -e HELLO="im on a boat" ./alpine.tar -- /bin/busybox sh -c 'echo $HELLO'

### signed distribution


all tarballs are signed by default with identitykit
check your own id with

	bali id

verify a package is built by an id

	bali verify alpine.tar.gz cDFJ6F4W6XEXAMPLE


verify before running stuff from the interwebs

	bali run -i cDFJ6F4W6XEXAMPLE https://example.com/alpine.tar.gz


### repositories


bali can fetch tarballs from http/s and sftp (scp)
it does intentionally not provide a way to `push` an image

to run a testing sftp server:

	docker run -d -p 2222:22  emberstack/sftp
	scp -P 2222  alpine.tar.gz  demo@localhost:/sftp/alpine.tar.gz
	# password is demo

	bali run -i $(bali id) scp://demo:demo@localhost:2222/sftp/alpine.tar.gz




### installing from source:

install docker-buildx and golang, then:

	go build
	cp bali /usr/local/bin







### other things you should know about

you can extract a tarball and just run it with systemd too

	systemd-run --wait --pty --collect --service-type=exec -p RootDirectory=$PWD -- busybox httpd -vfp 8080


