\pagebreak

# Kuvaus työmallista

Tämän työn kuluessa syntyi työmalli, jota kutsun *notkeaksi tietomallin paranteluksi*. Työmalli on parhaimmillaan tilanteissa, joissa ohjelmiston sovellusaluemalli sisältää monimutkaisia ja vain erityisalan asiantuntijalle aukeavia käsitteitä ja käsitesuhteita. Eduksi on myös, mikäli sovelluksen tekninen vaativuus ei ole kovin poikkeuksellinen. Tyypillinen bisnessovellus, jossa painopiste on sovellusalueessa, on hyvä kohde tälle työmallille.

Tämän työmallin pääperiaate on, että **sanat, kaaviot ja koodi** ovat kolme kommunikaation muotoa, jotka täydentävät toisiaan. Kuvaan seuraavassa tämän työmallin keskeiset ominaispiirteet.

#### Lyhyet iteraatiot
Lyhyet iteraatiot, joiden välissä pidetään suunnittelutapaaminen, ovat ehdoton edellytys tietomallin ripeälle kehittämiselle. On tärkeää, että iteraation kuluessa syntyy käyttökelpoinen ohjelmistoversio, jonka avulla mallin toimivuutta voidaan testata ja todentaa.

#### Keskusteleva suhde tuoteomistajan ja kehittäjän välillä
Koska tavoitteena on luoda kieli, jota voivat käyttää niin ohjelmoijat kuin liiketoimintaväkikin, sen kehittämiseen luontevin ja todennäköisesti ainoa tapa on rakentaa mallia keskustelevalla otteella.

#### Käyttäjätarinoihin pohjautuva työlista
Ketterän kehityksen työkalupakista peräisin oleva ajatus yksinkertaisista käyttäjätarinoista soveltuu hyvin tietomallin kehittämisen lähtökohdaksi. Kun huomion keskipisteenä ovat ne asiat, joita käyttäjä voi ohjelmistolla tehdä, on myös syntyvä malli lähempänä alan realismia.

#### Keskittyminen rajapinnan rakenteeseen ohjelmiston rakenteen sijasta
Keskeinen kysymys työtä tehtäessä on, ilmaiseeko rajapinta sovellusalueen ja ongelmakentän riittävän monipuolisesti. Teknisiin yksityiskohtiin, ohjelmointikieliin ja kirjastoihin keskittymisen sijasta huomio kannattaa pitää juuri rajapinnan ilmaisemassa käsiteverkossa.

#### Rajapintaskeeman rakentaminen käsitteiden pohjalta
GraphQL-rajapintaskeema kannattaa rakentaa ennenkuin kirjoittaa skeeman toteuttavaa koodia. Näin kielen käsitteet ja niiden väliset suhteet tulevat formaalisti ilmaistuksi. Ohjelmakoodin kirjoittamisen aikana skeema saattaa myös tarkentua, ja silloin kannattaa muutokset tehdä välittömästi.

#### Koodin ja mallin pitäminen lähekkäin
Välttämätön osa tätä työtyyliä on koodin ja mallin vastaavuus. Mallissa käytettävät käsitteet on löydyttävä koodista, ja koodissa tulisi olla lähinnä vain nämä käsitteet ja niiden väliset suhteet sellaisina, kuin ne \glslink{ubilang}{kaikenkattavassa kielessä} ilmenevät.

#### Voimakkaat refaktoroinnit
Voimakkaat refaktoroinnit ovat keino muokata koodin esittämästä mallista joustava ja ilmaisuvoimainen. Nämä refaktoroinnit vaativat ehdottomasti tuekseen jämerän yksikkötestisetin. Sen rakentaminen onnistuu käytännössä vain testit edellä tekemällä.

#### Ohjelmoinnissa vastaan tulleet ongelmat jatkosuunnittelun lähtökohtina
Suunnittelutapaamisten ja ohjelmointiprosessin välinen yhteys ei saa olla vain yksisuuntainen. Mikäli suunnittelutapaaminen nähdään ainoana osana prosessia, jossa suunnittelua tapahtuu ja ohjelmointi pelkästään suunnitelmien mekaanisena toteuttamisena, hyödyt tästä työskentelytyylistä jäävät hyvin vähäisiksi. Ohjelmointiprosessi on suunnittelutyön toisenlainen vaihe, ja siinä ilmenevät ongelmat ovat oivallinen maaperä seuraavan suunnittelutapaamisen aiheiksi.

Esittelen työmallin kuvassa \ref{tyomalli}.

![\label{tyomalli} Kuva työmallista](illustration/malli/notkea_tietomallin_parantelu2-1.png)

## Työmallin vahvuuksia
Tämän työmallin tuloksena syntyvä ohjelmisto tai ohjelmiston osa on notkea ja helposti muokattavissa. Lisäksi sen rakenne mukailee hyvin läheisesti sovellusalan sisäistä logiikkaa. Tämä läheinen yhteys tekee helpoksi tietomallin jatkokehittämisen, kuten uusien ominaisuuksien lisäämisen tai olemassaolevien muuttamisen. Kun sovellusalan toimintatavat muuttuvat, vastaa ohjelmistoon tehtävän muutoksen suuruus sovellusalalla tapahtuvan muutoksen suuruutta.

Tiheän kehityssyklinsä vuoksi tämä työmalli on myös suhteellisen hallittava ja ennustettava: ohjelmiston toimintojen tila on liiketoimintaeksperttien tutustuttavissa viikoittain. Tätä tietoa on mahdollista käyttää jäljellä olevan työmäärän arvioinnissa. Tiheä kehityssykli ja käyttäjätarinoihin pohjaava työlista myös suojaavat tarpeettoman työn tekemiseltä. Prosessissa syntyy lähinnä sellaista koodia, joka tarvitaan käyttäjälle näkyvien ominaisuuksien toteuttamiseen.

Koska työtyyli on keskusteleva ja ohjelmiston rakenne pyritään pitämään avoimena muutoksille, on muutoksien tekeminen mahdollista koko kehitysprosessin ajan, ja tarvittaessa vielä hyvinkin loppuvaiheessa prosessia. GraphQL-rajapintaskeeman kehittäminen on hyvä tapa dokumentoida tätä jaettua kieltä ja erottaa kielen käsitteet muusta koodista. 

## Työmallin haasteita
Tämä työmalli vaatii ohjelmoijalta paljon. Se edellyttää jatkuvaa kiinnostusta sovellusalueen piirteistä, ja laajaa tarkkaavuutta suunnittelutapaamisten keskuisteluissa. Lisäksi se edellyttää kykyä sietää epävarmuutta ja muuttaa suunnitelmia usein ja isosti. Teknisellä tasolla työmalli edellyttää kykyä joustavan ohjelmiston suunnittelemiseen, laajojen refaktorointien tekemiseen kireässä aikataulussa pysyen ja tiukkaa keskittymistä niihin päämääriin, jotka mallin kehittämisessä on kulloinkin asetettu.

Jotta tällainen työmalli voi olla hedelmällinen tuotantotasoisen ohjelmiston tekemisessä, se edellyttää myös, että työtyyli ohjelmoijan ympärillä vastaa tällaista tekemisen tapaa. Liiketoimintavetoisella suunnittelulla on vaikutuksia paitsi ohjelmistotuotannon prosessiin, myös sitä ympäröiviin prosesseihin, kuten asiakastarpeiden kokoamiseen ja tulevan kehitystyön suunnittelemiseen.

## Työmallin vaihtoehtojen punnitsemista

Monimutkaisten sovellusalueiden kanssa työskenteleminen on haaste joka tapauksessa. Olisi houkuttelevaa ajatella, että tällaisen monimutkaisuuden hallitseminen, asiakkaan tarpeiden ymmärtäminen ja tietomallin hahmotteleminen kuuluisi jollekulle muulle kuin ohjelmoijalle. Tällöin liiketoiminta-alasta ymmärtävä henkilö voisi kirjoittaa määrittelydokumentin, ja ohjelmoijan tehtäväksi jäisi määrittelyn mukaisen ohjelmiston toteuttaminen. Tällaisen työtavan haasteena kuitenkin on, että koodi ja määrittely voivat erkaantua nopeastikin toisistaan. Käytettävään ohjelmointiympäristöön liittyvät rajoitteet saattavat estää määrittelyn mukaisen mallin toteuttamisen. Tällöin malli lohkeaa kahdeksi: määrittelyn mukainen, tarkkaan suunniteltu malli jää paperille, ja koodiin päätyy kehitystyön ohessa nopeasti improvisoitu vaihtoehtoinen versio.\cite{evans:ddd}

Toinen vaihtoehto on ketterä, iteratiivinen kehitystyyli ilman kaikenkattavaa kieltä. Tässä prosessissa käyttäjävaatimuksia toteutetaan viikko viikolta, ja kehittäjät saavat iteraation päätyttyä palautetta siihen mennessä valmiiksi saadun ohjelmiston pohjalta. Yhteistä kieltä ei kuitenkaan pyritä rakentamaan, eikä kehittäjien edellytetä kirjoittavan sovellusalueen logiikkaa mukailevaa koodia. Riskinä on, että kehitystyön kuluessa ilmaantuu sellaisia käyttäjävaatimuksia, joita on hankala sovittaa olemassaolevaan ohjelmistoon. Koska koodi ei noudata yhteistä jaettua kieltä, voi kehittäjien koodiin kirjoittama malli poiketa suurestikin siitä, miten sovellusalueen ekspertit asiat ymmärtävät.\cite{evans:ddd}

Molemmissa edellä esitetyissä vaihtoehtoisissa tyyleissä kehitystahti hidastuu ja työ vaikeutuu prosessin edetessä, mikäli esitetyt riskit toteutuvat. Myös riski koodin laadun heikentymisestä on olemassa, mikäli ohjelmistoon joudutaan nopeasti tekemään muutoksia uusien käyttäjävaatimusten pohjalta.
