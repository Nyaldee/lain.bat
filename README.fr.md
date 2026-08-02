# lain.bat

<p align="center">
  <img src="lain.gif" alt="lain.bat">
</p>

*[Read in English](README.md)*

> [!CAUTION]
> À utiliser à tes risques et périls, sans aucune garantie. Sauvegarde tes fichiers et crée un point de restauration au préalable.

Script batch personnel et interactif pour optimiser et débloater une
installation fraîche de Windows 11 : réglages système/registre, configuration
NVIDIA, plan d'alimentation, désactivation des services inutiles et de la
télémétrie, etc. — le tout via un menu en ligne de commande, pas besoin de
lire le code pour l'utiliser.

Base recommandée : **Windows 11 IoT Enterprise LTSC 2024**

```
en-us_windows_11_iot_enterprise_ltsc_2024_x64_dvd_f6b14814.iso
```

## Utilisation

Exécute ce code dans une invite de commandes élevée, ou télécharge le script
et lance-le avec les privilèges administrateur.

```
curl -s -L -o %Temp%\lain.bat https://github.com/Nyaldee/lain.bat/raw/main/lain.bat && %Temp%\lain.bat
```

> [!NOTE]
> Si tu as besoin d'un navigateur web.
> ```
> curl -s -L -o %userprofile%\desktop\brave_installer-x64.exe https://brave-browser-downloads.s3.brave.com/latest/brave_installer-x64.exe
> ```

## Licence

Copyright (C) 2026 Nyaldee. Distribué sous licence [GNU General Public License v3.0](LICENSE) — voir le fichier `LICENSE` pour le texte complet.
