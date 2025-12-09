En prod sur Render :  
 – le formulaire fonctionne, je suis bien redirigé vers `/merci`,  
 – mais je **ne reçois aucun email**,  
 – et **la ligne n’apparaît pas dans mon Google Sheet**,  
 alors qu’en local tout marche correctement avec le même scénario.

Côté Render :  
 – Les variables SMTP (`SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`, `NOTIFY_TO`) sont configurées et identiques à mon `.env` local.  
 – La variable `APPS_SCRIPT_WEBHOOK` est définie sur l’URL de mon Apps Script (à vérifier si tu vois une incohérence).

Merci de :

1. Regarder dans `server.js` comment sont gérés :  
    – l’envoi d’email (nodemailer),  
    – l’appel du webhook `APPS_SCRIPT_WEBHOOK`.

2. Faire en sorte que pour chaque validation :  
    – l’email soit envoyé **ou**, en cas d’échec SMTP, que l’erreur soit loggée clairement avec le détail (host, port, code d’erreur),  
    – l’appel Apps Script soit fait **ou**, en cas d’erreur (timeout, 4xx/5xx), que l’erreur soit loggée avec le status et le body de la réponse.

3. Vérifier spécifiquement la différence entre local et Render :  
    – config SMTP (host, port, TLS/secure, firewall depuis Render),  
    – URL et permissions de `APPS_SCRIPT_WEBHOOK` (est-ce que le script accepte bien les requêtes POST anonymes de Render ?).

4. Garantir que, même si mail ou webhook échouent, la route `/api/selection` renvoie quand même une réponse claire au front (ce qui semble déjà être le cas), mais que les logs Render permettent de savoir **pourquoi** l’email/Sheet ont échoué.

5. Me donner une checklist simple :  
    – format exact attendu pour `APPS_SCRIPT_WEBHOOK`,  
    – config SMTP recommandée (host, port, secure true/false) pour un hébergement comme Render.

Je vais ensuite relancer un test en prod et te remonter les éventuels messages d’erreur précis des logs Render.

