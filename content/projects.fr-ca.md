+++
author = "Kevin Goyette"
title = ""
date = "2021-09-10"
description = "Voici la liste de mes projets."
tags = [
    "projets"
]
categories = [
    "projets"
]
series = ["Mes compétences"]
aliases = ["projets"]
+++


# kevin@blog:\~$ ls projets


{{< rawhtml >}}
<div style="margin-top: 7rem;"></div>
{{< /rawhtml >}}
## Moniteur d'API pour les accès aux fichiers sur le système
J'ai développé une application qui permet de monitorer tous les accès aux fichiers sur windows incluant les canaux nommés([Named pipes](https://docs.microsoft.com/fr-ca/windows/win32/ipc/named-pipes)). J'ai bâti cette application à la base afin de pouvoir connaître l'endroit où une certaine application extrayait ses fichiers.
L'application est écrite en C et utilise des [hooks](https://fr.wikipedia.org/wiki/Hook_(informatique)) de fonctions afin de pouvoir capture les appels aux APIs 
du système de fichiers.

[J'ai écrit un post à propos de ce projet.](/fr-ca/posts/fs_capture/)



{{< rawhtml >}}
<div style="margin-top: 7rem;"></div>
{{< /rawhtml >}}
## Service web pour les captures d'écran(Développement en cours)
Je développe présentement un service web qui permet le téléversement de capture d'écran(image ou vidéo). 
Cette application vous permet de téléverser vos captures sur mon serveur ou bien sur votre propre serveur.

[J'ai écrit un post à propos de ce projet.](/posts/screen_capture/)




