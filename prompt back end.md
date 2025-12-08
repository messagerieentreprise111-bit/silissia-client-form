Tu es mon assistant dev.  
 Important : **ne modifie pas la logique existante** (formulaire déjà en place, vérification du domaine, envoi au backend, email interne, etc.).  
 Tu dois seulement :

1. T’assurer que les bons champs sont présents côté front, avec les bons `name`, dans **un seul formulaire**.

2. Envoyer ces champs au backend comme aujourd’hui.

3. Faire en plus un appel POST JSON vers une URL Apps Script (webhook) pour remplir un Google Sheet.

---

## **1\. FRONT – Champs à avoir dans le formulaire (names obligatoires)**

Sur la page d’onboarding (celle après le paiement Stripe), il doit y avoir **un seul `<form>`** qui contient tous ces champs :

1. Prénom et nom

   * Label : “Prénom et nom”

   * `name="fullName"`

   * Champ obligatoire

2. Nom de l’entreprise

   * Label : “Nom de l’entreprise”

   * `name="company"`

   * Champ obligatoire

3. Adresse email actuelle

   * Label : “Adresse email actuelle”

   * `name="currentEmail"`

   * Champ obligatoire

   * C’est l’email sur lequel on enverra les accès

4. Question “Domaine / email déjà existant ?” (radios)

   * Deux choix sous la même question

   * `name="hasExistingDomain"`

   * Valeurs :

     * `no` → “Non, aucun domaine / email pro n’existe aujourd’hui”

     * `yes` → “Oui, un domaine ou une adresse existe déjà”

5. Nom affiché sur les emails

   * Titre affiché : “Nom affiché sur vos emails”

   * Texte explicatif : “Ce nom apparaîtra comme expéditeur lorsque vous enverrez des emails.”

   * Exemples affichés : “Jean Dupont, Cabinet Martin, Atelier Lefèvre…”

   * `name="displayName"`

   * Champ obligatoire

6. Début de l’adresse avant le @

   * Label : “Début de l’adresse”

   * Exemple : `contact`

   * `name="localPart"`

   * Champ obligatoire

7. Nom de domaine saisi pour vérification

   * Champ où l’utilisateur tape son idée de domaine (ex : boulangeriedupont.fr)

   * `name="requestedDomain"`

8. Nom de domaine final choisi

   * Quand l’utilisateur choisit une variante de domaine dans les résultats (ex : `rire.fr`), tu dois enregistrer le domaine finalement retenu sous :

   * `name="chosenDomain"`

   * Exemple de valeur : `boulangeriedupont.fr`

9. Comportement à ajouter :

   * Quand l’utilisateur clique sur une variante, afficher clairement l’adresse finale du type :  
      “Adresse email choisie : {localPart}@{chosenDomain}”

   * Juste en dessous, ajouter un bouton de confirmation du style :  
      “Je confirme cette adresse email”

   * Le domaine ne doit être considéré comme définitivement choisi (et `chosenDomain` rempli) **qu’après** clic sur ce bouton de confirmation.

   * C’est seulement à ce moment-là que le message de validation vert doit s’afficher.

10. Commentaires (optionnel)

    * Label : “Commentaires ou précisions (optionnel)”

    * `name="comment"`

    * Champ facultatif

Tout ceci doit être envoyé **dans le même formulaire**, avec un seul bouton de validation (par exemple “Créer mon adresse email professionnelle”), vers le même endpoint backend qu’aujourd’hui.

---

## **2\. BACKEND – Ce que tu dois faire avec ces champs**

Après soumission du formulaire d’onboarding, le backend doit recevoir au minimum :

* `fullName`

* `company`

* `currentEmail`

* `hasExistingDomain`

* `requestedDomain`

* `chosenDomain`

* `localPart`

* `displayName`

* `comment`

La logique actuelle doit être conservée :

* traitement existant

* envoi d’un email interne, etc.

Je veux ajouter **une étape en plus** :

* faire un appel **HTTP POST JSON** vers une URL Apps Script (webhook) pour écrire ces informations dans un Google Sheet.

### **Détails du webhook**

* URL Apps Script  :  
  https://script.google.com/macros/s/AKfycbx0qaiBqkQC3yJL7mQRtmIi5LB1dNh-W85GvLec5IuA48BoLS90xup-HR0gpzOu3zvapQ/exec

À chaque soumission de formulaire, le backend doit :

1. Récupérer les champs ci-dessus (`req.body` ou équivalent).

2. Continuer le comportement existant (mail, réponse, etc.).

3. En plus, envoyer un POST JSON vers l’URL du webhook avec ce format :

`{`  
  `"fullName": "...",`  
  `"company": "...",`  
  `"currentEmail": "...",`  
  `"hasExistingDomain": "...",`  
  `"requestedDomain": "...",`  
  `"chosenDomain": "...",`  
  `"localPart": "...",`  
  `"displayName": "...",`  
  `"comment": "..."`  
`}`

4. Si l’appel au webhook échoue, cela **ne doit pas bloquer** le reste du traitement :

   * la réponse au client

   * l’email interne  
      doivent continuer à fonctionner normalement.

---

Résultat attendu :

* Front : un seul formulaire qui envoie tous les champs listés avec les `name` exacts, et une confirmation explicite de l’adresse email finale choisie.

* Back : même fonctionnement qu’aujourd’hui, **\+** envoi de ce JSON vers l’URL Apps Script à chaque soumission de formulaire.

