serve:
	cd www; \
	hugo -D serve

all:
	cd www; \
	hugo -d ../docs/ -b https://thalium.github.io/blog/
