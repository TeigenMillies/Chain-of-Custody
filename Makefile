.PHONY: all clean

all: bchoc

bchoc: bchoc.py
	@command -v dos2unix >/dev/null 2>&1 \
		&& dos2unix $< || echo "Skipping dos2unix (not installed)"
	cp $< $@
	chmod +x $@

clean:
	rm -f bchoc