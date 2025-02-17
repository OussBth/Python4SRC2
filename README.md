# **Python4SRC2 - Gestion des Services via SSH**

Ce projet Python permet de gérer à distance l'installation, la configuration, et la maintenance de services tels qu'Apache, vsftpd, et OpenLDAP via SSH. Il offre également des outils pour la gestion des utilisateurs Linux.

---

## **Fonctionnalités principales**
- **Gestion des paquets** : Installation, mise à jour, suppression et vérification.
- **Serveur Web (Apache)** :
  - Configuration de nouveaux sites virtuels.
  - Gestion des fichiers de configuration.
  - Activation ou suppression des sites.
- **Serveur FTP (vsftpd)** :
  - Configuration rapide des connexions anonymes, locales et d'écriture.
  - Visualisation de la configuration actuelle.
- **OpenLDAP** :
  - Installation et configuration non-interactive.
  - Ajout et gestion d'utilisateurs LDAP.
- **Gestion des utilisateurs Linux** :
  - Création et suppression d'utilisateurs.
  - Modification des mots de passe.
  - Liste des groupes utilisateurs.
- **Gestion du réseau** :
  - Configuration des interfaces réseau.
  - Configuration des DNS.

---

## **1. Prérequis**

### a) Python et dépendances
1. **Installer Python 3** sur la machine locale.
2. Installer la bibliothèque `paramiko` :
   ```bash
   pip install paramiko
   ```
   ou
   ```bash
   pip3 install paramiko
   ```

### b) Machine distante
- Une machine distante fonctionnant sous **Debian/Ubuntu** ou une distribution similaire.
- SSH doit être installé et activé sur cette machine.

### c) Utilisateur SSH
1. Un utilisateur existant avec un mot de passe.
2. Des droits sudo peuvent être requis pour certaines fonctionnalités.

---

## **2. Structure du projet**

```
Python4SRC2/
├── sshpackagemanager.py    # Classes pour gérer les paquets, Apache, FTP, LDAP, utilisateurs, réseau.
├── main.py                 # Menu principal et logique du script.
├── README.md               # Documentation du projet.
```

---

## **3. Configuration préalable**

### a) Configuration sudoers (facultatif)
Si vous souhaitez limiter les commandes disponibles pour un utilisateur non-admin, éditez le fichier sudoers :
```bash
sudo visudo
```
Ajoutez une ligne similaire à :
```bash
Cmnd_Alias APACHE_CONF = /usr/bin/cat /etc/apache2/sites-available/*.conf
user ALL=(ALL) NOPASSWD: APACHE_CONF
```

---

## **4. Utilisation**

### a) Préparer la machine locale
1. **Cloner le dépôt GitHub** :
   ```bash
   git clone https://github.com/OussBth/Python4SRC2.git
   ```
2. **Accéder au répertoire** :
   ```bash
   cd Python4SRC2
   ```

### b) Lancer le script
1. Exécuter le script principal :
   ```bash
   python main.py
   ```
2. Fournir les informations SSH :
   - Adresse IP ou nom d'hôte.
   - Nom d'utilisateur et mot de passe SSH.
3. Naviguer dans les menus pour :
   - Installer des paquets.
   - Configurer Apache, FTP ou LDAP.
   - Gérer les utilisateurs Linux.
   - Configurer le réseau et les DNS.

---

## **5. Fonctionnalités en détail**

### a) Gestion des paquets
- **Installation** :
  ```bash
  sudo apt-get install -y <nom_du_paquet>
  ```
- **Suppression** :
  ```bash
  sudo apt-get remove -y <nom_du_paquet>
  ```
- **Vérification** :
  ```bash
  dpkg -l | grep <nom_du_paquet>
  ```

### b) Apache
- Ajout d'un site virtuel avec un port personnalisé.
- Activation et rechargement automatique du service Apache.

### c) FTP (vsftpd)
- Configuration des paramètres comme `anonymous_enable`, `local_enable` et `write_enable`.

### d) OpenLDAP
- Installation et configuration non-interactive via `debconf-set-selections`.

### e) Gestion des utilisateurs Linux
- Création avec home directory :
  ```bash
  sudo useradd -m <nom_utilisateur>
  ```
- Modification de mot de passe :
  ```bash
  echo '<nom_utilisateur>:<mot_de_passe>' | sudo chpasswd
  ```

### f) Gestion du réseau
- Configuration des interfaces réseau.
- Configuration des DNS.

---

## **6. Sécurité**

- Limitez les privilèges d'accès en configurant le fichier sudoers.
- N'utilisez pas `NOPASSWD: ALL` sauf si nécessaire.
- Assurez-vous que les ports SSH sont sécurisés et que seuls les utilisateurs autorisés peuvent se connecter.

---

## **7. Dépannage**

### Problèmes courants
1. **SSH échoue** :
   - Vérifiez l'adresse IP et les informations d'identification.
   - Assurez-vous que le service SSH est actif sur la machine distante.
2. **Commandes sudo refusées** :
   - Vérifiez les règles dans `/etc/sudoers`.

---

## **8. Contribution**

- Les contributions sont les bienvenues ! Veuillez soumettre vos pull requests ou signaler des problèmes dans la section [Issues](https://github.com/OussBth/Python4SRC2/issues).

---

## **9. Licence**

Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

---