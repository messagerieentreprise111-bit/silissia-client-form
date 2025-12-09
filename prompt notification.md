Je veux que l’envoi d’email de notification ne passe plus du tout par SMTP (Gmail ou autre) en prod, mais par l’API SendGrid.

Contexte :  
 – Le backend tourne sur Render.  
 – J’ai déjà ajouté dans les variables d’environnement Render :  
 – `SENDGRID_API_KEY` (clé API SendGrid valide)  
 – `NOTIFY_TO` (adresse qui doit recevoir les notifications)  
 – `SMTP_FROM` (adresse d’expéditeur, ex : contact@silissia.com)

Ce que je veux fonctionnellement :

1. Quand un client valide le formulaire (le flux normal qui finissait avant par m’envoyer un mail “Nouveau choix de domaine : …”), l’email doit désormais être envoyé via SendGrid, pas via SMTP.

2. Le mail doit garder la même structure que ce que j’avais avant :  
    – Sujet : `Nouveau choix de domaine : <domaine>`  
    – Corps texte avec :  
    – “Un client a confirmé un domaine.”  
    – Domaine choisi  
    – Début d’adresse (la partie avant le @)  
    – Email du client

3. En prod (Render), si `SENDGRID_API_KEY` est présent, aucune tentative de connexion SMTP ne doit être faite : tout doit passer par SendGrid.

4. L’envoi d’email doit rester non bloquant pour le client : si SendGrid échoue, le formulaire doit quand même se terminer normalement, mais l’erreur doit être loguée clairement dans les logs serveur.

5. En local, tu peux garder un comportement plus souple (par exemple continuer à utiliser l’ancien système si SendGrid n’est pas configuré), mais en prod c’est SendGrid qui doit être utilisé.

6. Une fois fini, fais un commit/push et assure-toi que le déploiement Render passe, puis donne-moi les instructions pour tester (URL avec session\_id de test \+ où regarder dans les logs si besoin).

Objectif final :  
 – À chaque validation réelle du formulaire en prod, je reçois un email de notification via SendGrid (instantané) avec les mêmes infos qu’avant.

