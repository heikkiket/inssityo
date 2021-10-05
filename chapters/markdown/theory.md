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
GraphQL-rajapinta koostuu tyypeistä, ja niitä edustavista olio-ilmentymistä.

Oheisessa esimerkissä näytetään tyyppien, ja sitä myötä olioiden väliset suhteet. ConsolidatedInvoice-tyyppisessä oliossa on sisällä invoices-kenttä, joka on lista Invoice-tyyppisiä olioita.

```GraphQL
type Query {
  consolidatedInvoices [ConsolidatedInvoice]
}

Type Invoice {
  number: Int
  sum: Float
  date: Date
}

type ConsolidatedInvoice {
  number: Int
  invoices: [Invoice]
}
```

### Query ja Mutation
Rajapintaan voi tehdä kyselyjä Query-tyyppisen juuriolion kautta. Tämän olion kentät vastaavat käytännössä niitä kyselyitä, joita rajapintaan voi tehdä. Kentät ovat ikäänkuin sisäänmenoaukkoja, joiden kautta oliorakenteita voi pyytää.

Kun oheisen esimerkin mukaisesti määritellystä GraphQL-rajapinnasta halutaan pyytää tietoja, tehdään kysely, joka kuvaa halutun oliopuun rakenteen tyyppien avulla:

```
{
  ConsolidatedInvoice {
    number
    invoices {
      number
      sum
    }
  }
}
```

Kyselyssä määritellään kentät, jotka palautuvassa datassa halutaan nähdä. Näin myös oliopuun syvyyttä voidaan kontrolloida. Oheisessa esimerkissä voidaan hakea paitsi lista koontilaskuista, haluttaessa myös jokaisen koontilaskun alle lista siihen kuuluvista laskuista.

Mutation - toiminto datan muuntelemiseen. Myös tämä palauttaa dataa

### Skeema
Rajapinnan tyypit, niille tehtävät kyselyt ja mutaatiot kuvataan skeemassa, GraphQL-kielen avulla.

 -Pohdintaa: Tämä skeema on varmaankin keskeinen nivelkohta Domain Driven Designin kanssa.
