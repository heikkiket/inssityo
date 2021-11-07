# Yhteenveto

Tässä insinöörityössä pyrittiin kohentamaan ohjelmiston tietomallia kehittämällä GraphQL-rajapinta \glsdisp{ddd}{sovellusaluevetoisen suunnittelun} keinoin. Tavoitteena oli parantaa nykyistä tietomallia ja luoda työprosessi tietomallin parantelemiseen. Samalla etsittiin vastausta kysymykseen, miten hyvin GraphQL-rajapinta teknologiana sopii tällaiseen prosessiin.

Saadakseni vastauksia kysymyksiin laadin pienen prototyyppisovelluksen, jonka tehtäväksi asetimme yhdessä tilaajan edustajien kanssa laskutukseen liittyvän konkreettisen ongelman ratkaisemisen. Keskeiset vastaukset työn nostamiin kysymyksiin tulivat juuri tämän sovelluksen kehitysprosessin kautta. Samalla kehitystyö muovasi lopullista työprosessia.

Tehdyn kokeilun perusteella GraphQL-rajapinta soveltuu hyvin sovellusaluevetoisen suunnittelun tarpeisiin. Tämä johtuu sen verkkomaisesta luonteesta, jolla on helppo mallintaa sovellusalueen käsitteiden keskinäisiä suhteita. Se, että GraphQL-verkko on nimenomaan rajapinta, helpottaa käsitteellisen mallin erottamista omaksi kokonaisuudekseen sovelluksen sisällä, ja irrottaa mallin konkreettisesta teknologiasta.

Koska GraphQL-rajapinta määritellään \glsdisp{dsl}{täsmäkielen} avulla, mallia on helppo muokata osana iteratiivista kehitysprosessia. Tämä mahdollistaa tutkimusmatkat ja kokeilut erilaisilla malleilla, kun käsitteiden välisiä suhteita voidaan muuttaa ensiksi skeemassa, ja vasta sitten taustalla olevassa koodissa.

Projektin aikana löysin kohteeksi valitun laskutuksen ongelman ratkaisevan tietomallin, ja luonnostelin *notkean tietomallin parantelun* periaatteet. Pääperiaate on, että **sanat, kaaviot ja koodi** ovat kolme tapaa kommunikoida tietomallista kehittäjien ja liiketoimintaihmisten välillä.

ietomallin toteuttaminen olemassaolevassa ohjelmistossa oli rajattu jo alunperinkin tämän projektin ulkopuolelle, ja se vaatisi vielä lisätyötä ja suunnittelua. Syntynyttä GraphQL-rajapintaskeemaa olisi mahdollista käyttää jatkotyön pohjana, ja näin parantaa myös vanhan ohjelmiston sisäistä logiikkaa.

GraphQL-kieli on pohjimmiltaan melko yksinkertainen, mutta joitain sen ominaisuuksia jäi tässä kartoittamatta. Esimerkiksi kielen tarjoamat Input Typet, jotka mahdollistavat tallennettavan datan esittämisen olioverkkona rajapintakyselyssä, sekä Union Typet, jotka tarjoavat tuen polymorfismille, jäivät tässä vaiheessa kartoittamatta. Jatkokysymykseksi siis jää, miten nämä monimutkaisemmat ominaisuudet niveltyvät yhteen \glsdisp{ddd}{sovellusaluevetoisen suunnittelun} kanssa.
