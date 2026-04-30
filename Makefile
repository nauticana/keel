.PHONY: build clean

build:
	go build -o bin/schemagen ./cmd/schemagen/

clean:
	rm -rf bin/
