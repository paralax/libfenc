all: pdf

ps: libfenc-manual.ps

pdf: libfenc-manual.pdf


libfenc-manual.pdf: *.tex *.bib
	pdflatex libfenc-manual
	bibtex libfenc-manual
	pdflatex libfenc-manual
	pdflatex libfenc-manual

libfenc-manual.ps: libfenc-manual.dvi
	dvips -t letter -Ppdf -o libfenc-manual.ps libfenc-manual.dvi

libfenc-manual.dvi: *.tex *.bib
	latex libfenc-manual
	bibtex libfenc-manual
	latex libfenc-manual
	latex libfenc-manual
clean:
	rm -f libfenc-manual.dvi libfenc-manual.ps libfenc-manual.pdf libfenc-manual.aux libfenc-manual.bbl libfenc-manual.log *.aux *.log

cvs:
	cvs update -d

view: libfenc-manual.pdf
	open libfenc-manual.pdf
