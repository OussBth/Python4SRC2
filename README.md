# README

Ce document explique les **étapes préalables** à mettre en place avant de pouvoir exécuter correctement le script principal (par exemple, `main.py`) qui utilise les classes définies dans `sshpackagemanager.py`. L’objectif est d’automatiser l’installation et la configuration de certains services (Apache, vsftpd, OpenLDAP…) et de proposer un accès “lecture seule” pour certains utilisateurs non-admin.

---

## 1. Prérequis

### a) Python et dépendances

1. **Installer Python 3** (sur la machine depuis laquelle vous allez lancer le script).  
2. **Installer la bibliothèque Paramiko** (gestion du SSH) :  
   ```bash
   pip install paramiko
   ```
   ou
   ```bash
   pip3 install paramiko
   ```

### b) Machine distante

- Assurez-vous de disposer d’une **machine cible** (Debian/Ubuntu ou similaire) accessible en SSH.  
- Vérifiez que **`ssh`** est installé et activé sur la machine distante.

### c) Utilisateur et droits

1. **Créer un utilisateur** (exemple : `ouss`) sur la machine distante.  
2. **Configurer** (ou non) son accès `sudo`, selon vos besoins :  
   - Les utilisateurs **admin** ont accès à toutes les commandes `sudo`.  
   - Les utilisateurs **non-admin** peuvent avoir un **accès restreint** à certaines commandes `sudo` (voir ci-dessous).  

---

## 2. Configuration “sudoers”

### a) Limiter l’accès `sudo` pour un non-admin (lecture seule)

Si vous souhaitez donner à un utilisateur (ex. `ouss`) la possibilité de **consulter** la configuration Apache/FTP sans lui donner les droits pour l’installer ou la modifier, **éditez** le fichier sudoers en utilisant :

```bash
sudo visudo
```

Dans ce fichier (ou dans un fichier séparé sous `/etc/sudoers.d/`), ajoutez :

```bash
Cmnd_Alias APACHE_CONF = /usr/bin/cat /etc/apache2/sites-available/*.conf
Cmnd_Alias FTP_CONF    = /usr/bin/grep -E '^(anonymous_enable|local_enable|write_enable)' /etc/vsftpd.conf

ouss ALL=(ALL) NOPASSWD: APACHE_CONF, FTP_CONF
```

- **Explications** :  
  - `APACHE_CONF` autorise `/usr/bin/cat` sur tous les fichiers `.conf` présents dans `/etc/apache2/sites-available/`.  
  - `FTP_CONF` autorise un `grep` précis sur `/etc/vsftpd.conf`.  
  - `NOPASSWD:` signifie que l’utilisateur `ouss` n’a pas besoin de saisir son mot de passe pour ces commandes.  
  - **Attention** : vérifiez bien les chemins exacts sur votre distribution (`which cat`, `which grep`).

### b) Accès total (optionnel)

Si vous voulez donner tous les droits sudo à un utilisateur (pour qu’il puisse installer, configurer, etc.) ou un groupe, définissez-lui une règle `ALL=(ALL) NOPASSWD:ALL` :

```bash
user ALL=(ALL) NOPASSWD: ALL
%group% ALL=(ALL) NOPASSWD: ALL
```

---

## 3. Configuration du script

### a) Variables importantes

- Dans votre script principal (`main.py` par exemple), ajustez la variable `hostname` pour pointer vers **l’adresse IP** ou le **nom de domaine** de la machine distante.  
- Assurez-vous également que l’**utilisateur** et le **mot de passe** fournis dans le script correspondent à ceux configurés sur la machine distante.

### b) Structure des fichiers

Vous devez disposer de **deux fichiers** principaux (à la racine de votre projet) :  
1. **`sshpackagemanager.py`** : contient toutes les classes (SSHPackageManager, WebManager, FTPManager, LDAPManager, LinuxUserManager, etc.).  
2. **`main.py`** : contient la logique de menus, d’authentification et les appels de méthodes.

---

## 4. Lancement du script

1. **Ouvrez un terminal** (ou console).  
2. Placez-vous dans le répertoire contenant vos fichiers Python :  
   ```bash
   cd /chemin/vers/mon-projet
   ```
3. Exécutez le script principal :  
   ```bash
   python main.py
   ```
   ou  
   ```bash
   python3 main.py
   ```
4. **Saisissez** l’identifiant et le mot de passe SSH de la machine distante lorsqu’il vous le demande.  
5. **Naviguez** dans les menus et testez les fonctionnalités (installation de paquets, lecture de config, etc.).

---

## 5. Notes et conseils

- **Sécurité** :  
  - Évitez de donner le droit `NOPASSWD: ALL` à des utilisateurs non fiables.  
  - Restreignez au maximum les commandes autorisées en `sudoers` (principe du moindre privilège).  
- **Dépannage** :  
  - Si le script **bloque** lors de la demande de mot de passe, vérifiez que vous l’exécutez dans un **vrai terminal** (et non via l’IDE) pour que `getpass` fonctionne correctement.  
- **Tests** :  
  - Vérifiez manuellement les commandes sous `sudo` si vous n’êtes pas sûr (par exemple : `sudo cat /etc/apache2/sites-available/default.conf`).

---

### Contact

Pour toute question ou problème, n’hésitez pas à ouvrir une **issue** ou à me contacter directement. Bon scripting !