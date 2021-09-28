main:
	xelatex -shell-escape -8bit main

markdown:
	pandoc chapters/markdown/käsittely.md -o chapters/käsittely.tex --top-level-division=chapter
	pandoc chapters/markdown/theory.md -o chapters/theory.tex
	pandoc chapters/markdown/kulku.md -o chapters/kulku.tex
	pandoc chapters/markdown/tulokset.md -o chapters/tulokset.tex
	pandoc chapters/markdown/yhteenveto.md -o chapters/yhteenveto.tex --top-level-division=chapter
	pandoc chapters/markdown/diary.md -o chapters/diary.tex --top-level-division=chapter

all: markdown main
