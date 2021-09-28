main:
	xelatex -shell-escape -8bit main

markdown:
	pandoc chapters/markdown/diary.md -o chapters/diary.tex --top-level-division=chapter
	pandoc chapters/markdown/theory.md -o chapters/theory.tex --top-level-division=chapter

all: markdown main
