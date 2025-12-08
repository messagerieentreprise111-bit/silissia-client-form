PROMPT

Voici ce que je veux :  
 Fais-moi un projet complet, clair et minimaliste, qui permet à un client de **taper un nom de domaine**, de savoir s’il est **disponible ou non**, et **si ce n’est pas disponible**, le système doit lui **proposer automatiquement d’autres options disponibles**.

Le fonctionnement doit être exactement le suivant :

1. Le client arrive sur une page après son paiement Stripe (Stripe n’est **pas** à intégrer ici).

2. Sur cette page, il tape un **nom de domaine** (ex : boulangeriedupont.fr).

3. Le système vérifie avec l’API (la clé est déjà dans `.env`).

4. Deux cas :

   * **Le domaine est disponible** → on le montre comme “disponible” et il peut le choisir.

   * **Le domaine est indisponible** → le système génère automatiquement plusieurs variantes (ex : .fr / .com / avec tirets / sans tirets / alternatives proches) et **n’affiche que celles qui sont réellement disponibles**.

5. Le client clique sur le domaine qu’il veut.

6. Son choix est enregistré.

7. Rien d’autre.

Dans le dossier du projet, il y a déjà un fichier `.env` contenant ma clé API pour vérifier les domaines.  
 Tu dois simplement l’utiliser **sans jamais afficher la clé**.

Ce que je veux que tu produises :

* un backend simple

* un frontend simple

* une route pour vérifier un domaine et générer des variantes disponibles

* une route pour enregistrer le choix final

* aucune fonctionnalité en plus

* aucune intégration Stripe

* aucun code inutile

Je veux un projet **propre, minimal, facile à comprendre**, qui fait uniquement :

Page → l’utilisateur tape un domaine → vérification →  
 • si dispo : on le propose  
 • si indispo : on propose uniquement des alternatives disponibles →  
 → choix → confirmation.

Explique ensuite comment lancer le projet.