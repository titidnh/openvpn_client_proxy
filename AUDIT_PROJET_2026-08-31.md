# Audit complet du projet openvpn_client_proxy

Date: 2026-08-31

## 1. Résumé exécutif

Le projet est techniquement avancé (kill switch, supervision, DoT, métriques, Tailscale), mais il a une zone de risque importante: le mode proxy applique des règles de filtrage très agressives qui peuvent casser des flux web légitimes (notamment médias/streaming), alors que le mode VPN seul fonctionne.

Le symptôme remonté (RTS fonctionne via VPN seul mais pas via VPN + proxy) est cohérent avec ce constat.

Niveau global:
- Architecture réseau: solide
- Robustesse opérationnelle: bonne, mais perfectible
- Cohérence docs/code: moyenne
- Qualité CI de non-régression: insuffisante
- Compatibilité web réelle avec filtrage: risquée en mode strict

## 2. Diagnostic du problème RTS (VPN OK, VPN+proxy KO)

## Hypothèse principale (très probable)

Le blocage vient des règles Privoxy et des filtres activés globalement.

Indices:
- Activation globale de filtres lourds dans [user.action](user.action#L25) à [user.action](user.action#L34)
- Blocage explicite de familles vidéo/analytics dans [default.action](default.action#L397) et [default.action](default.action#L398)
- Blocage global analytics/session replay dans [default.action](default.action#L698)
- Règles de suppression/cookies agressives dans [default.action](default.action#L794) et suivantes

Effet probable:
- Le player RTS dépend potentiellement de domaines annexes (CDN, télémétrie player, consent, session, auth edge) qui sont bloqués alors qu’ils sont nécessaires au flux.
- Résultat: VPN seul passe (pas de filtrage HTTP), VPN+proxy échoue (filtrage actif).

## Hypothèses secondaires

- CONNECT/flux spécifiques partiellement incompatibles selon le player (moins probable ici).
- Altération JS/HTML par filtres regex trop invasifs dans [default.filter](default.filter#L117) et [user.filter](user.filter#L16).

## 3. Points à corriger (priorité haute)

## P0 - Corriger la stratégie de filtrage pour éviter la casse applicative

1. Introduire deux profils de filtrage:
- Profil normal (par défaut): filtrage modéré
- Profil strict: filtres agressifs actuels

2. Désactiver par défaut les filtres les plus cassants sur tout le trafic:
- remove-js-trackers
- anti-fingerprint
- block-ads-js-aggressive-2026

Référence activation actuelle: [user.action](user.action#L28), [user.action](user.action#L29), [user.action](user.action#L34)

3. Ajouter des exceptions de compatibilité pour RTS dans user.action (whitelist ciblée domaine player/CDN).

## P0 - Corriger une anomalie de fichier de filtre

La ligne suivante contient un retour littéral dans le commentaire qui laisse penser à une corruption de bloc:
- [default.filter](default.filter#L90)

Texte observé:
- Sales Intelligence & B2B Headers (2026) suivi de \n avant la regex.

Action:
- Nettoyer ce bloc pour éviter tout comportement inattendu lors du parsing.

## P0 - Rendre le healthcheck réellement représentatif

Le healthcheck actuel valide surtout l’écoute locale du proxy, avec un test local non représentatif:
- répétition commentaire: [healthcheck.sh](healthcheck.sh#L53), [healthcheck.sh](healthcheck.sh#L55), [healthcheck.sh](healthcheck.sh#L57)
- test local: [healthcheck.sh](healthcheck.sh#L73)

Action:
- Tester une URL externe fiable via proxy (avec fallback multiple), pas une URL interne factice.
- Séparer readiness (démarrage) et liveness (santé continue).

## P1 - Corriger les incohérences documentation vs implémentation

1. Valeur DNS secondaire incohérente:
- Docs: [README.md](README.md#L327)
- Runtime image: [Dockerfile](Dockerfile#L73)

2. Backoff documenté à 60s mais code à 120s:
- Docs: [README.md](README.md#L707)
- Code: [start.sh](start.sh#L2647)

3. Description healthcheck obsolète dans la doc:
- [README.md](README.md#L723) et [README.md](README.md#L724)
- ne reflète pas le script actuel [healthcheck.sh](healthcheck.sh#L1)

## P1 - Renforcer la CI avant publication image

Workflow actuel orienté build/push uniquement:
- [docker-publish.yml](.github/workflows/docker-publish.yml#L1)

Manques:
- shellcheck/shfmt
- tests de non-régression proxy
- smoke tests VPN+proxy
- validation règles Privoxy

## 4. Choses à rajouter (recommandé)

## Ajouts fonctionnels

1. Mode compatibilité streaming
- Variable exemple: PROXY_PROFILE=normal|strict
- En normal: réduire blocages vidéo/JS destructifs

2. Whitelist runtime
- Variable exemple: PROXY_ALLOWLIST
- Permet d’ajouter rapidement des domaines non bloqués sans éditer les fichiers image

3. Endpoint de diagnostic proxy
- Script testant: DNS local, résolution domaine cible, CONNECT 443, requête HEAD via proxy
- Export résultat dans logs JSON

4. Option de logs Privoxy de debug temporaire
- Aujourd’hui logs off: [privoxy.config](privoxy.config#L22), [privoxy.config](privoxy.config#L23)
- Ajouter toggle DEBUG_PRIVOXY=true pour activer logs en incident

## Ajouts qualité/ops

1. Tests automatiques de compatibilité web
- Matrice de sites tests: streaming, banque, e-commerce, médias
- Vérifier: code HTTP, temps de réponse, erreurs CONNECT

2. Workflow CI PR dédié
- lint shell
- build image
- tests conteneur avec profils normal/strict
- test healthcheck réel via proxy

3. Runbook incident
- Procédure claire pour diagnostiquer un site cassé (désactivation progressive des filtres, whitelist, collecte logs)

## 5. Plan de correction concret (ordre conseillé)

1. Corriger user.action pour un profil normal par défaut.
2. Ajouter exceptions RTS ciblées.
3. Corriger healthcheck pour test externe réaliste + fallback.
4. Aligner README avec le comportement réel.
5. Ajouter CI de non-régression avant push image.

## 6. Protocole de test pour ton cas RTS

Objectif: isoler précisément la règle qui casse RTS.

1. Test A - VPN seul
- Accès RTS sans proxy, noter comportement.

2. Test B - VPN+proxy avec filtrage minimal
- Désactiver temporairement les filtres agressifs.
- Si RTS fonctionne, la cause est confirmée côté filtrage.

3. Test C - Réactivation progressive
- Réactiver filtres un par un:
- remove-js-trackers
- anti-fingerprint
- block-ads-js-aggressive-2026
- Identifier le premier qui recasse RTS.

4. Test D - Whitelist définitive
- Ajouter exception domaine(s) RTS/CDN détectés.
- Revalider plusieurs sessions.

## 7. Risques résiduels si pas de correction

- Faux positifs de santé conteneur
- Régressions silencieuses à chaque évolution des filtres
- Incompatibilités fréquentes sur sites dynamiques/streaming
- Temps de support plus long lors d’incidents

## 8. Conclusion

Ta base est bonne et ambitieuse. Le principal axe d’amélioration n’est pas le VPN lui-même, mais la politique de filtrage proxy: elle est actuellement trop agressive pour être le mode par défaut.

Pour ton problème RTS, la priorité est de passer à un profil de filtrage normal + whitelist ciblée, puis d’encadrer ça avec des tests de non-régression en CI.
