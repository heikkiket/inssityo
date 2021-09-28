\vspace{21.5pt}

# Aineisto ja menetelmät

Keskeisten käsitteiden esittely

## Domain Driven Design
(Sovellusalakeskeinen suunnittelu)
(Liiketoimintavetoinen suunnittelu)

### Knowledge crunching
### Ubiquitous Language

### Mallin ilmaiseminen ohjelmistossa

 - Domain-malli on ohjelmistossa omana erillisenä kerroksenaan, puhtaasti ja erillään muista.
 - Entity - entiteetti, eli olio, jolla on identiteetti
 - Assosiaatio, eli kulkusuunta

 Pohdintaa: - Evans suosittaa kerroksittaista arkkitehtuuria, ja erillistä kerrosta, jossa Domain-malli elää. Luonteva paikka tälle voisi olla GraphQL-rajapinnan takana.

## GraphQL

### Tyyppijärjestelmä
GraphQL-rajapinta koostuu tyypeistä

### Query ja Mutation
Rajapintaan voi tehdä queryjä - nämä ovat ikäänkuin sisäänmenoaukkoja, joiden kautta oliorakenteita voi pyytää
Mutation - toiminto datan muuntelemiseen. Myös tämä palauttaa dataa

### Skeema
Rajapinnan tyypit, niille tehtävät kyselyt ja mutaatiot kuvataan skeemassa, GraphQL-kielen avulla.

 -Pohdintaa: Tämä skeema on varmaankin keskeinen nivelkohta Domain Driven Designin kanssa.
