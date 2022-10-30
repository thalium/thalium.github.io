HUGO_VERSION=0.95.0

serve:
	docker run --rm -it \
	  -v $(PWD)/www:/src:rw \
	  -p 1313:1313 \
	  klakegg/hugo:$(HUGO_VERSION) \
	  -D serve

build:
	docker run --rm -it \
	-v $(PWD)/www:/src:rw \
	-v $(PWD)/docs:/tmp/thalium:rw \
	-u $(shell id -u ${USER}):$(shell id -g ${USER}) \
	klakegg/hugo:$(HUGO_VERSION) \
	-d /tmp/thalium -b https://thalium.github.io/blog/

all: build

.PHONY: all build serve
