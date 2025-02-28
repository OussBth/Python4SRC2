# **Python4SRC2 - Gestion des Services via SSH**

Ce projet Python permet d'administrer à distance une machine Linux via SSH. Il facilite l'installation, la configuration et la gestion de plusieurs services, notamment :

- **Gestion des paquets** (installation, suppression, mise à jour, vérification)
- **Administration des serveurs web** (Apache, Nginx, PHP)
- **Gestion des serveurs FTP** (vsftpd)
- **Administration LDAP** (OpenLDAP, gestion des utilisateurs et unités organisationnelles)
- **Gestion des utilisateurs Linux** (ajout, suppression, modification de mot de passe, gestion des groupes)
- **Configuration réseau** (interfaces réseau, IP statique/DHCP, DNS)

## **1. Prérequis**

### a) Environnement et dépendances
- **Python 3** doit être installé sur la machine locale.
- Bibliothèques Python requises :
  ```bash
  pip install paramiko
  ```

### b) Machine distante
- Une distribution Linux (Debian/Ubuntu ou similaire) disposant d'un service SSH actif.
- Des droits sudo pour l'exécution de commandes administratives (requis pour plusieurs fonctionnalités).

---

## **2. Structure du Projet**

```
Python4SRC2/
├── main.py                # Interface et menus interactifs de l'application.
├── classes.py   # Classes de gestion SSH dédiées aux paquets, Apache, FTP, LDAP, utilisateurs et réseau.
├── colored_formatter.py   # Formatter de log personnalisé avec couleurs.
├── README.md              # Cette documentation.
```

---

## **3. Installation et Configuration**

1. **Cloner le dépôt GitHub :**
   ```bash
   git clone https://github.com/VotreCompte/Python4SRC2.git
   cd Python4SRC2
   ```

2. **Installer les dépendances :**
   ```bash
   pip install paramiko
   ```

3. **(Optionnel) Configuration sudoers :**  
   Pour éviter de demander le mot de passe pour certaines commandes, éditez le fichier sudoers :
   ```bash
   sudo visudo
   ```
   Ajoutez par exemple :
   ```bash
   # Alias permetant de limiter les commandes
   Cmnd_Alias APACHE_CONF = /bin/cat /etc/apache2/sites-available/*.conf
   Cmnd_Alias FTP_CONF    = /usr/bin/grep -E '^(anonymous_enable|local_enable|write_enable)' /etc/vsftpd.conf
   # Pour un utilisateur
   ouss ALL=(ALL) NOPASSWD: APACHE_CONF, FTP_CONF
   # Pour les groupes
   %admin  ALL=(ALL) NOPASSWD: ALL
   %lambda ALL=(ALL) NOPASSWD: APACHE_CONF, FTP_CONF
   ```

---

## **4. Utilisation**

1. **Lancer le script principal :**
   ```bash
   python main.py
   ```

2. **Au démarrage, entrez l'adresse IP ou le nom d'hôte de la machine distante, puis vos identifiants SSH.**
3. **Naviguez ensuite dans le menu principal qui présente plusieurs sous-menus dédiés :**
   - **Gestion des paquets**
   - **Gestion web (Apache, Nginx, PHP)**
   - **Configuration du FTP (vsftpd)**
   - **Gestion LDAP (OpenLDAP, utilisateurs, groupes)**
   - **Administration des utilisateurs Linux**
   - **Configuration réseau (interfaces, IP, DNS)**

---

## **5. Fonctionnalités en Détail**

### a) Gestion des paquets classiques
- **Installation / Mise à jour / Désinstallation**  
  Utilise `apt-get` pour manipuler les paquets.  
  Exemple de commandes exécutées :
  - `sudo apt-get install -y <paquet>`
  - `sudo apt-get remove -y <paquet>`
  - `dpkg -l | grep <paquet>`

### b) Serveurs Web (Apache2, Nginx, PHP)
- Installation automatique avec suppression des conflits.
- Activation, désactivation et gestion des sites.

### c) Serveur FTP (vsftpd)
- **Configuration de vsftpd**  
  Mise à jour des paramètres tels que `anonymous_enable`, `local_enable` et `write_enable`.
- **Redémarrage du service vsftpd.**

### d) Serveur LDAP (OpenLDAP)
- **Installation et configuration automatisée** via un script Bash généré temporairement.
- **Ajout / Suppression d’utilisateurs LDAP et d’Unités Organisationnelles (OU).**

### e) Utilisateurs Linux
- Ajout, suppression et modification de mot de passe.
- Gestion des groupes et attribution des permissions.

### f) Configuration Réseau
- Activation/désactivation des interfaces.
- Attribution d'une IP statique ou configuration DHCP.
- Gestion des serveurs DNS via `/etc/resolv.conf`.

---

## **6. Sécurité**

- **Privilèges restreints :**  
  Configurez correctement les accès sudo pour limiter les commandes disponibles selon l'utilisateur.
- **Connexion SSH :**  
  Assurez-vous que seuls les utilisateurs autorisés puissent se connecter à la machine distante.

---

## **7. Dépannage**

- **Échec de la connexion SSH :**  
  Vérifiez l'adresse, les identifiants et que le service SSH est bien actif sur la machine distante.
- **Erreur sur les commandes sudo :**  
  Assurez-vous que les règles dans `/etc/sudoers` sont correctement configurées.
- **Dépendances manquantes :**  
  Installez le module requis tel que `paramiko`.

---

## **8. Contribution**

Les contributions sont les bienvenues !  
- **Pull Requests** : N’hésitez pas à proposer des améliorations via des pull requests.
- **Issues** : Signalez les problèmes ou les bugs dans la section [Issues](https://github.com/OussBth/Python4SRC2/issues).

---

## **9. Licence**

Ce projet est sous licence MIT.  
Voir le fichier [LICENSE](LICENSE) pour plus de détails.