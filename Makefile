latex: bibliography glossaries latex_raw

latex_raw:
	xelatex -shell-escape -8bit main

bibliography:
	biber main

glossaries:
	makeglossaries main

markdown:
	for file in $$(cd chapters/markdown; ls *.md); do \
		pandoc chapters/markdown/$$file -o chapters/$$file.tex --top-level-division=chapter;\
	done;

all: markdown latex

clean:
	rm main.acn main.acr main.alg main.aux main.bcf main.blg main.glg main.glo main.gls main.ist main.log main.out main.run.xml main.toc main.upa main.upb

.PHONY: markdown
