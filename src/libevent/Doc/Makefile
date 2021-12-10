FIGS=flow.fig

GEN_EPS=$(FIGS:.fig=.eps)
EPS=$(GEN_EPS)
PDF=$(EPS:.eps=.pdf)
TEXMAIN=libevent.tex
TEXREST=style.tex

all: libevent.pdf

libevent.pdf: $(TEXMAIN) $(TEXREST) $(PDF)

# Generate an .eps file from a .fig file
%.eps : %.fig
	/usr/bin/X11/fig2dev -L eps $< $@ > /dev/null 2>&1

# Generate a .pdf file from a .tex file
%.pdf : %.tex
	pdflatex $<
	pdflatex $<

# Generate a .pdf file from a .eps file
%.pdf : %.eps
	epstopdf $< > /dev/null 2>&1

clean:
	rm -f $(GEN_EPS) $(PDF) *.dvi libevent.pdf *.aux *.log *~

.phony: clean
