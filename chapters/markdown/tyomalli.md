\pagebreak

# Kuvaus työmallista

Tämän työn kuluessa syntyi työmalli, jota kutsun *notkeaksi tietomallin paranteluksi*. Työmalli on parhaimmillaan tilanteissa, joissa ohjelmiston sovellusaluemalli sisältää monimutkaisia ja vain erityisalan asiantuntijalle aukeavia käsitteitä ja käsitesuhteita. Eduksi on myös, mikäli sovelluksen tekninen vaativuus ei ole kovin poikkeuksellinen. Tyypillinen bisnessovellus, jossa painopiste on sovellusalueessa, on hyvä kohde tälle työmallille.

Kuvaan seuraavassa tämän työmallin keskeiset ominaispiirteet.

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

## Työmallin haasteita
Tämä työmalli vaatii ohjelmoijalta paljon. Se edellyttää jatkuvaa kiinnostusta sovellusalueen piirteistä, ja laajaa tarkkaavuutta suunnittelutapaamisten keskuisteluissa. Lisäksi se edellyttää kykyä sietää epävarmuutta ja muuttaa suunnitelmia usein ja isosti. Teknisellä tasolla työmalli edellyttää kykyä joustavan ohjelmiston suunnittelemiseen, laajojen refaktorointien tekemiseen kireässä aikataulussa pysyen ja tiukkaa keskittymistä niihin päämääriin, jotka mallin kehittämisessä on kulloinkin asetettu.

Jotta tällainen työmalli voi olla hedelmällinen tuotantotasoisen ohjelmiston tekemisessä, se edellyttää myös, että työtyyli ohjelmoijan ympärillä vastaa tällaista tekemisen tapaa. Liiketoimintavetoisella suunnittelulla on vaikutuksia paitsi ohjelmistotuotannon prosessiin, myös sitä ympäröiviin prosesseihin, kuten asiakastarpeiden kokoamiseen ja tulevan kehitystyön suunnittelemiseen.
