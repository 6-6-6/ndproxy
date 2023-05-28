.PHONY: build clean install
 

build:
	cargo build --release

install:
	mkdir "${DESTDIR}/${prefix}/bin/" -p
	mkdir "${DESTDIR}/etc/" -p
	${INSTALL} target/release/ndproxy "${DESTDIR}/${prefix}/bin/"
	${INSTALL} example.config.toml "${DESTDIR}/etc/ndproxy.toml"

clean:
	mkdir target -p
	rm target -rf
