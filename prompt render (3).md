Je veux déployer cette app sur **Render.com** en tant que **Web Service Node/Express**.

Contexte :

* C’est la page/formulaire **post-paiement Stripe** de mon funnel.

* Le front utilise des endpoints `/api/check`, `/api/selection`, `/api/completion` déclarés dans `server.js` (Express), avec `nodemailer` et un appel à Domainr via `FASTLY_API_TOKEN`.

Tâches à faire pour rendre le projet prêt pour Render :

1. **Structure du projet**

Assure-toi qu’on a un `package.json` propre, avec au minimum :

 `{`  
  `"name": "silissia-client-form",`  
  `"version": "1.0.0",`  
  `"main": "server.js",`  
  `"scripts": {`  
    `"start": "node server.js"`  
  `}`  
`}`

*   
  * Garde `server.js` comme point d’entrée du serveur Express.

2. **Port et compatibilité Render**

Le serveur doit écouter **obligatoirement** sur `process.env.PORT` (et pas un port en dur). Exemple :

 `const port = process.env.PORT || 3000;`  
`app.listen(port, () => {`  
  ``console.log(`Server running on port ${port}`);``  
`});`

*   
3. **Variables d’environnement**

   * Tout ce qui est sensible doit être lu via `process.env` :

     * `FASTLY_API_TOKEN` (appel Domainr)

     * identifiants SMTP pour `nodemailer` (ex : `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`)

     * toute autre clé ou secret éventuel

   * Ne laisse **aucun token ou mot de passe en dur** dans le code.

4. **Build / assets front**

Si le front est en HTML/CSS/JS simple, sers les fichiers statiques depuis Express (par exemple dossier `public/`) avec :

 `app.use(express.static('public'));`

*   
  * Si tu utilises un bundler (Vite/Webpack/React/etc.), ajoute le script de build dans `package.json` (ex : `"build": "vite build"`), et assure-toi que le front buildé est servi correctement par Express en production.

  * Donne-moi les commandes de build claires à utiliser sur Render :

    * **Build command** (par ex. `npm install && npm run build` ou juste `npm install` si pas de build)

    * **Start command** : `npm start`

5. **Endpoints API**

   * Vérifie que les routes `/api/check`, `/api/selection`, `/api/completion` :

     * répondent bien en JSON,

     * gèrent correctement les erreurs (try/catch, status codes cohérents),

     * n’exposent aucune info sensible dans les réponses.

6. **Intégration Stripe (post-paiement)**

   * La page principale doit fonctionner comme **page de succès Stripe**.

   * Je vais définir dans Stripe `success_url = https://client.silissia.com`.

   * Option bonus : prévoir la possibilité d’accepter un paramètre `session_id` (`?session_id={CHECKOUT_SESSION_ID}`) pour éventuellement vérifier côté serveur la validité de la session via l’API Stripe avant d’afficher le formulaire (mais ce n’est pas obligatoire pour V1, seulement si tu peux le faire proprement).

7. **README pour Render**

   * Ajoute un fichier `README.md` simple qui explique :

     * les variables d’environnement à définir,

     * la commande de build,

     * la commande de start,

     * et rappelle que le serveur écoute sur `process.env.PORT`.

Objectif :

* Que je puisse pousser le projet sur GitHub,

* Le connecter sur Render comme Web Service Node,

* Définir les variables d’environnement dans Render,

* Et que tout fonctionne en **Free plan**, sans avoir à modifier le code.

*Quand tout est prêt, vérifie que :*  
– *la commande `npm start` fonctionne localement sans erreur,*  
– *les endpoints `/api/check` etc. répondent bien,*  
– *et que je peux tester une version buildée.*

*Je veux un livrable final qui tourne sur Render Free, sans erreur, sans configuration supplémentaire, et dont les endpoints répondent correctement après déploiement.*