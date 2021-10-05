# Lähtökohdat ja tavoitteet

## Nordhealth Oy lyhyesti


Nordhealth Oy on vuonna 2001 perustettu ohjelmistopalveluyritys, joka tekee toiminnanohjausjärjestelmiä kahdelle eri toimialalle: Provet Cloud -järjestelmää eläinlääkäriklinikoille ja Diarium-järjestelmää terapeuteille. Molemmat järjestelmät ovat web-pohjaisia sovelluksia. Niitä käytetään kirjautumalla web-selaimen kautta. (Tästä puuttuu perustietoja, kuten työntekijöiden määrä, liikevaihto tms.)

Nordhealthia voisi luonnehtia tyypilliseksi ohjelmistoalan yritykseksi: se tekee erityisalalle suunnattua toiminnanohjausjärjestelmää. Tyypillinen on myös järjestelmien kehityskaari: alunperin ne ovat olleet työpöytäsovelluksia, ja siitä Nordhealth on muuntanut ne LAMP-alustalla toimiviksi web-sovelluksiksi. Kun Web on kehittynyt, on otettu suunnaksi sovellusten siirtäminen julkiseen pilveen, ja käyttöliittymän rakentaminen erilliseksi yhden sivun JavaScript-sovellukseksi.

Diarium on Nordhealthin kahdesta järjestelmästä vanhempi. Se on suunnattu terapeuteille: fysio-, toiminta-, puhe- ja psykoterapeuteille. Järjestelmä on laajentunut yksinkertaisesta potilaskortistojärjestelmästä suurenkin terapia-alan yrityksen tarpeita vastaavaksi toiminnanohjausjärjestelmäksi, ja se on lisäksi myös Valviran tarkoittama A-luokan potilastietojärjestelmä. Diariumia käyttävä terapeutti voi siis lähettää käyntikirjaukset potilastiedon sähköiseen Kanta-rekisteriin.

## Insinöörityön tavoite

Työn tavoitteena on selvittää, onko ohjelmiston tietomallia mahdollista parannella rakentamalla GraphQL-rajapinta.

Lisäksi työn myötä on tavoitteena löytää parempi tietomalli osaan Diarium-sovellusta.

Kolmas tärkeä tavoite on kehittää työmenetelmä, jonka avulla tietomallia on mahdollista korjata.

Projektin edetessä rakennan pienen GraphQL-rajapinnan ja sitä hyödyntävän prototyyppisovelluksen. Tämä toimii kokeilukenttänä, jonka kautta työmenetelmää ja tietomallia etsitään.
