# Lähtökohdat ja tavoitteet

## Nordhealth Oy lyhyesti

Nordhealth Oy on vuonna 2001 perustettu ohjelmistopalveluyritys, joka tekee toiminnanohjausjärjestelmiä kahdelle eri toimialalle: Provet Cloud\cite{ProvetCloudHomepage} -järjestelmää eläinlääkäriklinikoille ja Diarium-järjestelmää\cite{DiariumHomepage} terapeuteille. Molemmat järjestelmät ovat web-pohjaisia sovelluksia. Niitä siis käytetään web-selaimen kautta.

Nordhealthia voisi luonnehtia tyypilliseksi ohjelmistoalan yritykseksi: se tekee erityisalalle suunnattua toiminnanohjausjärjestelmää. Tyypillinen on myös järjestelmien kehityskaari: alunperin ne ovat olleet työpöytäsovelluksia, ja siitä Nordhealth on muuntanut ne LAMP[^1]-alustalla toimiviksi web-sovelluksiksi. Kun Web on kehittynyt, on otettu suunnaksi sovellusten siirtäminen julkiseen pilveen, ja käyttöliittymän rakentaminen erilliseksi yhden sivun JavaScript-sovellukseksi.

[^1]: Linux, Apache, MySQL, PHP

Diarium on Nordhealthin kahdesta järjestelmästä vanhempi. Se on suunnattu terapeuteille: fysio-, toiminta-, puhe- ja psykoterapeuteille. Järjestelmä on laajentunut yksinkertaisesta potilaskortistojärjestelmästä suurenkin terapia-alan yrityksen tarpeita vastaavaksi toiminnanohjausjärjestelmäksi, ja se on lisäksi myös Valviran tarkoittama A-luokan potilastietojärjestelmä. Diariumia käyttävä terapeutti voi siis lähettää käyntikirjaukset potilastiedon sähköiseen Kanta-rekisteriin.

## Tarve työlle

Diariumin ikä näkyy tietomallin monimutkaisuutena. Vuosien saatossa tehty kehitystyö on tehnyt ohjelmiston joistain osista hankalia ymmärtää. Ohjelman kehittäminen on myös aloitettu aikana, jolloin sovelluksia ei automaattisesti tehty yhden sivun sovelluksiksi. Nykyään tämä kuitenkin on normi, ja ohjelmaan on jo vuosia kehitetty REST-rajapintaan nojaavia toiminnallisuuksia.

Voisiko rajapintaa rakentaessa myös parantaa ohjelmiston sisäistä tietomallia? Tämä säästäisi aikaa ja vaivaa, ja nopeuttaisi ohjelmiston jatkokehitystä.

## Insinöörityön tavoite

Tämän insinöörityön tavoitteena on selvittää, onko ohjelmiston tietomallia mahdollista parannella rakentamalla GraphQL-rajapinta. Lisäksi työn myötä on tavoitteena löytää parempi tietomalli osaan Diarium-sovellusta.

Kolmas tärkeä tavoite on kehittää työmenetelmä, jonka avulla tietomallia on mahdollista korjata. Näin työssä tehtyjä havaintoja on mahdollista hyödyntää jatkossa.

Projektin edetessä rakennan pienen GraphQL-rajapinnan ja sitä hyödyntävän prototyyppisovelluksen. Tämä toimii kokeilukenttänä, jonka kautta työmenetelmää ja tietomallia etsitään.
