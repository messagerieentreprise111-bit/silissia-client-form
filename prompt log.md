**Prompt pour l’IA dev (à coller dans VS Code)**

Tu vas intervenir sur un backend Node.js \+ Express hébergé sur Render, qui gère un formulaire post-paiement Stripe pour créer des adresses email pro.

Contexte fonctionnel (très important, lis bien) :

* Front statique (HTML/CSS/JS) servi par Express, avec un formulaire principal sur “/”.

* Endpoints clés côté backend :

  * GET /api/check : vérifie la disponibilité d’un nom de domaine via une API externe (Domainr/Fastly, token FASTLY\_API\_TOKEN).

  * GET /api/completion : vérifie, à partir d’un session\_id Stripe, si le formulaire a déjà été complété (en s’appuyant sur data/completions.json).

  * POST /api/selection : reçoit toutes les données du formulaire (session\_id, fullName, company, currentEmail, hasExistingDomain, requestedDomain, chosenDomain, localPart, displayName). Ce endpoint :

    * protège contre les doublons via completions.json,

    * logge la sélection dans selections.json,

    * déclenche en “non bloquant” :

      * un email de notification interne via SendGrid (NOTIFY\_TO, SENDGRID\_API\_KEY, SMTP\_FROM),

      * un POST JSON vers APPS\_SCRIPT\_WEBHOOK (Google Apps Script) pour écrire dans un Google Sheet (“Suivi Clients – Auto”).

* Les données de complétion et de sélection sont stockées dans des fichiers JSON dans le dossier data/ :

  * data/completions.json : garde “anti-doublon” pour les sessions Stripe / emails.

  * data/selections.json : log brut de toutes les sélections client.

* L’appli tourne sur Render, donc les logs sont visualisés dans l’onglet Logs de Render (stdout/stderr).

* Objectif business : visibilité claire sur les erreurs (SendGrid, Apps Script, API domaine, lecture/écriture de JSON), sans changer le comportement métier existant.

Ta mission :  
 Mettre en place un système de logging structuré et cohérent dans tout le backend, sans casser l’existant, de façon exploitable dans les logs Render, et suffisamment sobre pour ne pas être verbeux.

Contraintes :

* Ne change pas la logique métier (validation de formulaire, anti-doublon, communication avec Apps Script, SendGrid, etc.).

* Ne rajoute pas de dépendance lourde type gros framework de logging ; si tu veux, tu peux faire un petit module maison.

* Ne loggue pas de données ultra-sensibles inutiles (pas de clés API, pas de secrets).

* Utilise uniquement la sortie standard (console) pour les logs, pas de fichiers locaux de logs persistants.

Tâches à réaliser (dans l’ordre logique) :

1. Créer un module de logging centralisé

   * Crée un petit module de type “logger” (par exemple dans un fichier dédié) qui expose au minimum trois niveaux : info, warn, error.

   * Chaque log doit être une seule ligne JSON sérialisée, incluant au moins :

     * level (info/warn/error),

     * scope (chaîne courte pour identifier le contexte : “domain-check”, “selection”, “sendgrid-notif”, “apps-script”, “express”, “process”, etc.),

     * message (phrase courte en anglais ou français, mais claire),

     * meta (objet optionnel avec les détails utiles : domain, session\_id, clientEmail, httpStatus, etc.),

     * timestamp au format ISO (new Date().toISOString()).

   * Le but est de permettre, dans les logs Render, de filtrer facilement par “scope” ou “level” et de comprendre rapidement ce qui se passe.

2. Instrumenter l’endpoint GET /api/check

   * Au début du handler, ajouter un log “info” avec scope “domain-check” indiquant qu’une vérification de domaine commence, avec le nom de domaine concerné.

   * Si le paramètre domain est manquant ou invalide :

     * log en “warn” avec scope “domain-check”,

     * renvoyer une erreur HTTP adaptée (400).

   * Autour de l’appel à l’API externe Domainr/Fastly :

     * en cas de succès : log “info” avec scope “domain-check” qui indique si le domaine est disponible ou pris, plus éventuellement quelques suggestions (sans spammer les logs).

     * en cas d’erreur / timeout / exception : log “error” avec scope “domain-check”, incluant le message d’erreur et le domaine concerné, puis renvoyer un code HTTP adapté (par exemple 502\) avec un message JSON générique.

3. Instrumenter l’endpoint POST /api/selection (endpoint critique)

   * Au tout début, log “info” avec scope “selection” indiquant qu’une nouvelle sélection de formulaire est reçue, avec au moins : session\_id, currentEmail, chosenDomain, localPart (ne loggue pas le contenu complet du formulaire si ce n’est pas utile).

   * Lors de la vérification anti-doublon (completions.json) :

     * si la session ou l’email sont déjà marqués comme complétés, log “warn” avec scope “selection” indiquant “Form already completed” avec session\_id et email, puis renvoie l’erreur actuelle (ne change pas le comportement métier).

   * Lors de l’écriture dans selections.json et de la mise à jour de completions.json :

     * log “info” avec scope “selection” quand l’écriture s’est bien passée (session et email marqués comme complétés).

     * en cas d’erreur de lecture/écriture sur ces fichiers JSON : log “error” avec scope “selection” avec le détail de l’erreur, et renvoie une réponse HTTP 500 générique au client.

   * La gestion des effets de bord (notification interne SendGrid, webhook Apps Script) doit se faire dans une fonction séparée (ou une logique claire), lancée “en arrière-plan” pour ne pas bloquer la réponse HTTP, mais chaque échec de ces effets de bord doit être loggé proprement (voir points suivants).

4. Logging autour de SendGrid (notification interne)

   * Dans la fonction qui envoie l’email interne via SendGrid (NOTIFY\_TO, SMTP\_FROM) :

     * log “info” avec scope “sendgrid-notif” avant l’envoi, en incluant au minimum NOTIFY\_TO, chosenDomain, currentEmail.

     * si l’envoi réussit : log “info” avec scope “sendgrid-notif” confirmant le succès, avec les éléments utiles (par exemple un identifiant de message si disponible).

     * si l’envoi échoue (exception, statut HTTP non-2xx, etc.) : log “error” avec scope “sendgrid-notif” incluant le message d’erreur et les infos utiles (email destinataire, domaine). Ne jette pas l’erreur jusqu’au client final : c’est une alerte interne, le but est de logguer, pas de casser le flux client.

5. Logging autour du POST vers APPS\_SCRIPT\_WEBHOOK (Google Apps Script)

   * Avant d’appeler APPS\_SCRIPT\_WEBHOOK (doPost côté Apps Script) : log “info” avec scope “apps-script” indiquant qu’on envoie une nouvelle ligne vers Google Sheets, avec session\_id, currentEmail, chosenDomain, localPart.

   * Si l’appel HTTP vers Apps Script réussit (code 2xx) : log “info” avec scope “apps-script” confirmant le succès, avec le code HTTP.

   * Si l’appel échoue (timeout, code non-2xx, exception) : log “error” avec scope “apps-script” avec le code HTTP, le message d’erreur, et éventuellement une partie du body de réponse si utile. Le flux client ne doit pas se casser pour autant : la priorité est de conserver une trace de l’échec.

6. Sécuriser la lecture/écriture des fichiers JSON (completions.json et selections.json)

   * Encapsuler la lecture/écriture de ces fichiers dans des fonctions utilitaires robustes.

   * Si le fichier JSON n’existe pas, est vide ou corrompu :

     * log “warn” avec scope “json-store” expliquant le problème (par ex. “completions.json missing or invalid, reinitializing”),

     * réinitialise proprement la structure en mémoire (par ex. un objet ou un tableau vide) et recrée le fichier sur disque.

   * En cas d’erreur d’IO (droit, disk full, etc.) : log “error” avec scope “json-store” avec l’erreur, et remonte une erreur contrôlée au code appelant (qui renverra un HTTP 500 générique).

7. Middleware global d’erreurs Express

   * Ajouter un middleware d’erreur Express à la fin de la configuration des routes, qui :

     * utilise le logger (scope “express”) pour logguer toute erreur non gérée (path, method, message d’erreur, stack).

     * renvoie une réponse JSON générique type { error: "Erreur interne." } avec un HTTP 500\.

   * Vérifier que ce middleware n’écrase pas les réponses d’erreurs déjà gérées spécifiquement dans les handlers (il doit capter seulement ce qui remonte non traité).

8. Gestion des erreurs globales du processus Node

   * Ajouter des handlers process.on(‘unhandledRejection’) et process.on(‘uncaughtException’) qui :

     * loggent via le logger, scope “process”, niveau “error”, avec le message et éventuellement la stack.

   * Ne pas faire de process.exit brutal pour l’instant (à moins que ce soit strictement nécessaire) afin de ne pas introduire de comportement inattendu sur Render ; logguer d’abord.

9. Propreté et lisibilité des logs

   * S’assurer que les logs ne sont pas verbeux au point de noyer les infos importantes :

     * log “info” seulement aux moments clés (début/fin logique d’un traitement, succès d’un appel externe important),

     * log “warn” pour les cas inattendus mais récupérables (fichier JSON corrompu mais recréé, formulaire déjà complété, paramètres manquants),

     * log “error” exclusivement pour les vraies erreurs (échec d’API externe, problème de lecture/écriture JSON, exception non gérée).

   * Vérifier que toutes les chaînes “scope” sont cohérentes et faciles à filtrer.

10. Tests manuels à prévoir

* Me laisser des instructions simples (en commentaire ou dans un petit fichier README) pour tester :

  * un cas nominal (formulaire normal, tout fonctionne) et voir quels logs apparaissent,

  * un cas où l’API domaine échoue (simuler une erreur) et vérifier que les logs “domain-check” sont parlants,

  * un cas où SendGrid renvoie une erreur (clés invalides, par exemple en staging) et voir les logs “sendgrid-notif”,

  * un cas où Apps Script renvoie une erreur (URL de webhook volontairement invalide) et lire les logs “apps-script”.

* Tu peux détailler une petite checklist de test dans un fichier texte/README pour moi.

Objectif final :  
 À la fin de ta modification, je veux :

* pouvoir ouvrir les logs Render et, en cherchant des scopes comme “selection”, “domain-check”, “sendgrid-notif”, “apps-script”, “json-store”, “express”, “process”, comprendre très vite :

  * ce qui a été tenté,

  * ce qui a réussi,

  * ce qui a échoué et pourquoi.

* sans changer la façon dont le client vit le parcours (pub → Stripe → formulaire → email d’accès).

Merci de me décrire brièvement dans un commentaire ou un petit README ce que tu as modifié (fichiers touchés et logique globale de logging).

---

Si tu veux ensuite, on fera exactement le même type de prompt ciblé pour la partie Stripe / webhook.

