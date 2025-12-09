Normalement je t’ai envoyé les captures d’écrans pour que tu vois de quoi je parle.

En prod sur Render, avec une URL du type :  
 `https://silissia-client-form.onrender.com?session_id=test123`

Quand je choisis un domaine disponible et que je clique sur **“Valider cette adresse”** :  
 – le bouton passe en “Envoi en cours…” pendant plusieurs dizaines de secondes / minutes,  
 – puis le message **“Impossible d’enregistrer le choix.”** s’affiche sous le champ domaine.

Tu m’avais indiqué que `data/selections.json` n’était pas commité et restait uniquement en local.  
 Je pense que c’est la cause : en prod, la route `/api/selection` essaye de lire/écrire dans ce fichier qui n’existe pas / pas initialisé, ce qui provoque une erreur serveur.

Merci de :

1. Confirmer dans les logs Render que `/api/selection` plante bien à cause de `data/selections.json` manquant ou illisible.

2. Corriger pour la prod en :  
    – soit committant un fichier `data/selections.json` initialisé (par exemple `[]`),  
    – soit en faisant en sorte que, si le fichier n’existe pas, il soit créé automatiquement avec une structure vide, sans faire planter l’API.

3. Faire en sorte que `/api/selection` renvoie toujours une réponse rapide :  
    – `200 { success: true }` si tout va bien,  
    – ou `400/500 { error: 'Message explicite…' }` en cas d’erreur,  
    mais **jamais** une requête qui reste bloquée plusieurs minutes.

4. Mettre un log clair côté serveur quand l’erreur “Impossible d’enregistrer le choix.” est renvoyée, pour qu’on puisse comprendre immédiatement la cause dans les logs Render.

Objectif : je clique sur “Valider cette adresse” →  
 – soit ça passe (succès, message de confirmation),  
 – soit ça échoue vite avec un message d’erreur clair,  
 mais plus de blocage long avec “Envoi en cours…”.

Mais si tu penses que le problème c’est autre chose je te laisse le champ libre pour agir.