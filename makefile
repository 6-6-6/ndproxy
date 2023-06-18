.PHONY: build clean install
 

build:
	cargo build --release

install:
	mkdir "${DESTDIR}/${prefix}/bin/" -p
	mkdir "${DESTDIR}/etc/" -p
	mkdir "${DESTDIR}/lib/systemd/system/" -p

	${INSTALL} target/release/ndproxy "${DESTDIR}/${prefix}/bin/"
	${INSTALL} example.config.toml "${DESTDIR}/etc/ndproxy.toml"
	${INSTALL} systemd/ndproxy.service "${DESTDIR}/lib/systemd/system/"

clean:
	mkdir target -p
	rm target -rf
