En local, la page de formulaire fonctionne bien, même avec les garde-fous activés.  
 Sur Render, à l’URL :  
 `https://silissia-client-form.onrender.com`  
 quand je teste un domaine (ex : `bobobi.fr`), j’ai l’interface qui me dit :  
 **“Formulaire déjà complété.”**  
 alors que je n’ai jamais validé ce formulaire sur cet environnement.

Contexte :  
 – Le build Render se passe bien, serveur “ready on http://localhost:10000”.  
 – Les variables d’environnement suivantes sont bien définies sur Render :  
 `FASTLY_API_TOKEN, SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM, NOTIFY_TO`  
 – `DISABLE_COMPLETION_GUARD` n’est **pas** défini en prod (comme prévu).

Merci de :

1. Localiser dans le code **la condition exacte** qui déclenche le message “Formulaire déjà complété.” (front et/ou backend).

2. M’expliquer la différence de comportement entre local et Render (origine : env vars, stockage externe, cookies, session Stripe, autre ?).

3. Adapter le code pour que :  
    – si on arrive sur la page sans passer par Stripe / sans contexte valide → on ait un message clair du type “Accès non valide” ou redirection,  
    – si on n’a **jamais** complété le formulaire pour cette session/domaine, même en prod, on puisse le remplir sans se faire bloquer par “Formulaire déjà complété”.

4. Ajouter éventuellement des logs côté serveur pour tracer le chemin qui mène à cette réponse, afin qu’on puisse diagnostiquer facilement si ça se reproduit.

Donne-moi aussi un exemple de réponse JSON renvoyée par `/api/check` dans le cas “Formulaire déjà complété” (status code \+ body), pour que je puisse vérifier moi-même via l’onglet Network.

