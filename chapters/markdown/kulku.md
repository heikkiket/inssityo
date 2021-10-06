\vspace{21.5pt}

# Työn kulku

Työn aluksi valitsimme yhdessä ohjaajani sekä tiimin tuoteomistaja Lauran kanssa aiheen työhön. Laskutusta koskevat osat ohjelmistossa ovat suhteellisen monimutkaisia, ja sisältävät käsitteellisiä epäselvyyksiä. Valitsimme laskutuksen sisältä tapauksen, jossa hoitokäynti tulee voida jakaa usealle eri maksajalle osoitetuille laskuille, ja nämä laskut tulee voida hyvittää itsenäisesti.

Tämän jälkeen ryhdyin pitämään tiimin tuoteomistaja Lauran kanssa kokokouksia, joissa suunnittelimme mallin rakennetta. Pyrin noudattamaan työskentelyssä Eric Evansin esittämää tiedon rouhimisen periaatetta, jossa suunnittelu ja ohjelmistokehitys limittyvät keskenään.

Pidimme lyhyitä suunnittelukokouksia, joissa pohdimme, millainen mallin tulisi olla. Kokousten välillä kirjoitin ohjelmiston, joka vastasi pohdintojamme. Seuraavassa kokouksessa katsoimme, miten ohjelma toimii, ja lisäsimme malliin uusia piirteitä.

Käytin apuvälineenä tussitaulua, johon piirsin erilaisia ehdotuksia malleiksi. Oleellista on, että taulun pystyi pyyhkimään nopeasti, ja piirtämään uuden mallin. Otimme myös valokuvia mallinnussession eri vaiheista. En kuitenkaan halunnut, että piirretyt mallit sanelevat ohjelmiston rakennetta. Tärkein mittari on ohjelmakoodi, ja sen ilmaisema rakenne. Piirrokset toimivat apuna, tämän rakenteen kuvaajina.

Ensimmäisesssä kokouksessa hahmottelimme yksinkertaisen mallin, jossa käynnit liitetään laskuihin, laskut koontilaskuihin ja koontilaskut hyvityslaskuihin. Toteutin tämän mallin parin viikon kuluessa, jonka jälkeen pidimme uuden tapaamisen. 

Tavoitteenani oli jokaisen tapaamisen myötä rakentaa hieman monipuolisempi ja paremmin ohjelmiston käyttäjien tarpeita vastaava malli. Toisinaan tällaiset laajentamispyrkimykset voivat myös johtaa äkilliseen läpimurtoon, jonka myötä syntyy \gls{deepermodel}.\cite{evans:ddd}

Tapaamisissa kävin joka kerta läpi, mitkä käsitteelliset asiat olivat ohjelmoidessa vaivanneet. Esimerkiksi toisella tapaamiskerralla esitin suurimmaksi ongelmaksi sen, että käynnin ja laskun välillä on suora kytkös. Ohjelmoidessa tämä kytkös tuli koko ajan huomioida, ja varoa aiheuttamasta ongelmia. Pyysin Lauraa kertomaan enemmän siitä, mitä käynnin laskuttaminen oikeastaan tarkoittaa, ja hän piti lyhyen yhteenvedon laskuttamisen periaatteista. Huomioni kiinnittyi puheessa esiintyneeseen termiin **Laskutusperuste**. Tämä tuntui valtavan kiinnostavalta, ja lähdimme tarkastelemaan sitä eri puolilta.

Tapaamisen jälkeisen viikon kehitystyötä ohjasi nyt uusi ajattelutapa: käyntiä sinänsä ei liitetä laskuun, vaan käynti laskutetaan, mikäli laskutusperuste täyttyy. Tämän tuloksena syntyi melko yksinkertainen malli:

~~~~~ {.ditaa .no-separation}
+--------------+       +--------------+       +----------------+
|  Appointment | ----> |  ServiceRow  | ----> |  ServiceCredit |
+--------------+       +--------------+       +----------------+
~~~~~

## Ubiquitous Language käytännössä

Kuuluisivatkohan nämä oikeastaan tulosten tarkastelun tai yhteenvedon alle?

Pitäessäni suunnittelukokouksia yhdessä tuoteomistajan kanssa, pyrin koko ajan
kuuntelemaan tarkalla korvalla, minkälaisia sanoja käytimme. Tällä tavoin
onnistuin nappaamaan joitain tärkeitä käsitteitä, joita pystyi käyttämään mallin
pohjana. Toisen kokouksemme aikana esiin noussut **Laskutusperuste** oli juuri
tällainen käsite.

Eric Evans mainitsee, että **Kaikenkattavan kielen** rakentamisessa oleellista
on löytää sanat, joita alan asiantuntijat käyttävät.

## Käsitekarttojen ja GraphQL-skeeman yhteys

Olin yllättynyt, miten täsmällisesti piirtämäni käsitekartat oli mahdollista ilmaista GraphQL-skeeman avulla. Olioiden suhteet siirtyivät vaivattomasti skeeman sisälle hierarkioiksi.
