# Tulokset

## Prototyyppiohjelman esittely

Prototyyppiohjelma on yksinkertainen yhden sivun selainsovellus. Sen avulla voi luoda käyntejä, laskuttaa niitä, koota laskuja koontilaskuiksi ja hyvittää yksittäisiä laskurivejä.

![\label{rakkine_default-view}Laskujen lisäysnäkymä](illustration/screenshots/Laskurakkine.png)

Ohjelman pääkäyttöliittymä on esitetty kuvassa \ref{rakkine_default-view}

Laskujen sisältöjä voi tarkastella, ja ohjelma laskee laskujen avoimet summat.

![\label{rakkine_dividing}Esimerkki käynnin jakamisesta usealle maksajalle](illustration/screenshots/Dividing.png)

Lisäksi käyttöliittymästä voi valita maksajan luotavalle laskulle. Mikäli maksajia valitaan useampia, ohjelma jakaa käynnit kahdelle eri maksajalle. Tämä on esitetty kuvassa \ref{rakkine_dividing}

![\label{rakkine_list-view}Ohjelman listanäkymä](illustration/screenshots/List-view.png)

Erillisessä listanäkymässä (Kuva \ref{rakkine_list-view}) voi tarkastella luotujen käyntien tilaa sekä laskutettavan myynnin tilaa. Ohjelma näyttää, onko käynti laskutettu vai laskuttamaton. Myynnin osalta ohjelma näyttää, miten myynti jakautuu eri maksajille, ja onko summa avoin, laskutettu vai hyvitetty.


![\label{rakkine_credited}Ohjelma näyttää, että yksittäinen laskurivi on hyvitetty](illustration/screenshots/credited.png)

Kuvassa \ref{rakkine_credited} on esitetty miten ohjelma näyttää hyvitetyn laskurivin.


Käytin asiakasohjelman tekemiseen niin vähän aikaa kuin mahdollista. Se näkyy tyylin hiomattomuutena. Luonnosmaisen näköinen ulkoasu myös kommunikoi muille prosessiin osallistuville, että ohjelmisto tai etenkään sen käyttöliittymä ei ole tarkoitettu tuotantokäyttöön, vaan apuvälineeksi erilaisten tietomallin piirteiden kartoittamiseen.

## Parannuksia tietomalliin
Viiden viikon aikana syntyi pieni malli laskutukseen tietorakenteen parantamiseksi. Lisäksi löytyi kaksi pientä ideaa, joita voi hyödyntää, kun ohjelmistoa kehitetään.

![\label{finalmodel1-again}Lopullinen malli](illustration/malli4.jpg)

Pieni malli laskutuksen parantamiseksi on esitetty kuvassa \ref{finalmodel1-again}. Se pitää sisällään ajatuksen käynnin muuttumisesta myynniksi, kun se saapuu laskutuksen piiriin. Oma erikoisuutensa on myös käynnin jakamiseen liittyvä jakoperuste.

Prototyypissä emme ottaneet kantaa, millä perusteella käynnin hinnan osittaminen eri maksajille tapahtuu. Käytännössä ohjelmassa on eri maksajatahojen kanssa tehtyjä sopimuksia, jotka määrittelevät ehtoja maksuosuuden suuruudesta. Jakoperuste on siis dynaamisesti muuttuva käsite, joka riippuu haluttuihin maksajiin ja käyntiin kytkettyyn hoitojaksoon yhdistyvistä sopimuksista.

![\label{finalidea1}Idea 1](illustration/final-idea-1.jpg)

Kaksi pientä ideaa ovat molemmat käyttökelpoisia erillään mallista. Ensimmäinen niistä on myynnin, myyntirivin ja hyvitysrivin välinen tiivis yhteysketju. Tämä idea (kuva \ref{finalidea1})mahdollistaa hyvin yksinkertaisen ja joustavan myynnin laskutus- ja hyvityslogiikan.

![\label{finalidea2}Idea 2](illustration/final-idea-2.jpg)

Toinen pieni idea on, että käynti kannattaisi erottaa selkeästi laskulle tulevasta myynnistä. Tällöin on mahdollista myös esimerkiksi vaihtaa myöhemmin maksajaa, jolta käynti laskutetaan, ilman että jo muodostettuihin laskuihin tarvitsee kajota. Tämä ajatus on esitetty kuvassa \ref{finalidea2}.
