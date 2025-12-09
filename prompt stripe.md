Mon flux réel est le suivant :

* Page de vente sur Système.io

* Bouton qui pointe vers un **Payment Link Stripe**

* Stripe redirige ensuite vers :  
   `https://silissia-client-form.onrender.com/?session_id={CHECKOUT_SESSION_ID}`

Je n’utiliserai **jamais** `/api/checkout/session` côté front, car le paiement ne démarre pas depuis Render.

Les variables d’environnement Stripe sont déjà configurées sur Render (en mode test) :

* `STRIPE_SECRET_KEY`

* `STRIPE_SETUP_PRICE_ID`

* `STRIPE_SUBSCRIPTION_PRICE_ID`

* `PUBLIC_BASE_URL` \= `https://silissia-client-form.onrender.com`

* `STRIPE_WEBHOOK_SECRET`

**Ne modifie pas cette configuration d’environnement** (ni les noms de variables).  
 Tu peux simplement laisser de côté les `*_PRICE_ID` si elles ne sont plus nécessaires dans le code.

Merci d’adapter le code comme suit :

1. **Supprimer entièrement le bouton “Payer” dans `public/index.html`**, ainsi que le code JS associé dans `public/main.js`.  
    Il ne doit rester aucun élément permettant de démarrer un paiement depuis Render.

2. **Supprimer la route `/api/checkout/session` dans le backend**, car elle ne sera pas utilisée dans mon flux réel.

3. Dans `public/main.js` :

   * Au chargement, récupérer `session_id` dans l’URL.

   * Si `session_id` est présent : appeler `/api/completion` comme déjà implémenté, et n’autoriser l’accès au formulaire que si la session Stripe est marquée payée via le webhook.

   * Si `session_id` est absent : rediriger directement vers `/acces-non-valide` (cas non légitime, quelqu’un qui arrive sur Render sans payer).

Objectif final :

* Le paiement démarre uniquement depuis Système.io via le Payment Link Stripe.

* Stripe redirige vers Render avec `session_id`.

* Le webhook \+ `/api/completion` sécurisent l’accès post-paiement au formulaire.

* La page Render ne doit plus afficher aucun bouton “Payer”, et il ne doit y avoir aucun chemin permettant de repayer depuis Render. Les variables Stripe restent en place pour le webhook et pour d’éventuelles évolutions, mais ne doivent pas être utilisées pour recréer une session Checkout côté front.

