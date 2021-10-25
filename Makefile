latex: bibliography glossaries latex_raw

latex_raw:
	xelatex -shell-escape -8bit main

bibliography:
	biber main

glossaries:
	makeglossaries main

markdown:
	pandoc chapters/markdown/introduction.md -o chapters/introduction.tex --top-level-division=chapter
	pandoc "chapters/markdown/lähtökohdat ja tavoitteet.md" -o chapters/lähtökohdat.tex --top-level-division=chapter
	pandoc chapters/markdown/theory.md -o chapters/theory.tex --top-level-division=chapter
	pandoc chapters/markdown/kulku.md -o chapters/kulku.tex --top-level-division=chapter
	pandoc chapters/markdown/tulokset.md -o chapters/tulokset.tex --top-level-division=chapter
	pandoc chapters/markdown/yhteenveto.md -o chapters/yhteenveto.tex --top-level-division=chapter
	pandoc "chapters/markdown/Liite 1 diary.md" -o chapters/diary.tex --top-level-division=chapter

all: markdown latex

clean:
	rm main.acn main.acr main.alg main.aux main.bcf main.blg main.glg main.glo main.gls main.ist main.log main.out main.run.xml main.toc main.upa main.upb
