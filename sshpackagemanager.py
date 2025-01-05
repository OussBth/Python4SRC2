import paramiko

class SSHPackageManager:
    """
    Classe de base qui gère la connexion SSH et propose des méthodes
    générales pour installer, supprimer, mettre à jour, vérifier des paquets.
    """

    def __init__(self, hostname, username, password):
        # On stocke les informations de connexion (hôte, user, mdp)
        self.hostname = hostname
        self.username = username
        self.password = password

        # On crée un client SSH Paramiko
        self.client = paramiko.SSHClient()
        # On autorise l'ajout automatique de la clé de l'hôte distant
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # On se connecte à la machine distante
        self.client.connect(hostname, username=username, password=password)

    def execute_command(self, command):
        """
        Méthode utilitaire pour exécuter une commande sur la machine distante.
        On force un environnement non-interactif (DEBIAN_FRONTEND=noninteractive).
        """
        command = f"export TERM=xterm DEBIAN_FRONTEND=noninteractive && {command}"
        stdin, stdout, stderr = self.client.exec_command(command)
        # On récupère la sortie standard et la sortie d'erreur
        return stdout.read().decode(), stderr.read().decode()

    def install_single_package(self, package):
        """
        Installe un seul paquet (apt-get install -y <package>).
        """
        print(f"[INFO] Installation du paquet {package}...")
        output, error = self.execute_command(f"sudo apt-get install -y {package}")
        if error.strip():
            print(f"[ERREUR] lors de l'installation de {package} : {error}")
        else:
            print(output)

    def install_packages(self, package_name):
        """
        Installe plusieurs paquets à la fois (séparés par un espace).
        1) apt-get update
        2) apt-get install pour chaque paquet
        """
        packages = package_name.split()

        # Mise à jour de la liste des paquets
        output, error = self.execute_command("sudo apt-get update")
        if error.strip():
            print(f"[ERREUR] lors du apt-get update : {error}")
        else:
            print(output)

        # Installation de chaque paquet
        for package in packages:
            self.install_single_package(package)

    def remove_package(self, package_name):
        """
        Supprime un paquet (apt-get remove -y)
        puis on exécute apt-get autoremove -y pour nettoyer.
        """
        print(f"[INFO] Suppression du paquet {package_name}...")
        output, error = self.execute_command(f"sudo apt-get remove -y {package_name}")
        if error.strip():
            print(f"[ERREUR] lors de la suppression de {package_name} : {error}")
        else:
            print(output)
            # Nettoyage
            self.execute_command("sudo apt-get autoremove -y")

    def verify_package(self, package_name):
        """
        Vérifie si un paquet est installé (dpkg -l | grep <package>).
        """
        print(f"[INFO] Vérification de l'installation de {package_name} avec dpkg...")
        output, error = self.execute_command(f"dpkg -l | grep {package_name}")
        if output.strip():
            print(f"[OK] Le paquet {package_name} est installé.")
            return True
        else:
            print(f"[INFO] Le paquet {package_name} n'est pas installé.")
            return False

    def update_package(self, package_name):
        """
        Met à jour un paquet s'il est déjà installé.
        Sinon, indique qu'il n'est pas installé.
        """
        if self.verify_package(package_name):
            print(f"[INFO] Mise à jour du paquet {package_name}...")
            output, error = self.execute_command(
                f"sudo apt-get update && sudo apt-get install --only-upgrade -y {package_name}"
            )
            if error.strip():
                print(f"[ERREUR] lors de la mise à jour de {package_name}: {error}")
            else:
                print(output)
        else:
            print(f"[INFO] Le paquet {package_name} n'est pas installé, aucune mise à jour nécessaire.")

    def close_connection(self):
        """
        Ferme la connexion SSH proprement.
        """
        self.client.close()
        print("[INFO] Connexion SSH fermée.")


class WebManager(SSHPackageManager):
    """
    Gère les actions spécifiques au serveur web (Apache2).
    Hérite de SSHPackageManager pour la connexion SSH et l'exécution de commandes.
    """

    def configure_apache2(self, site_name, port=80):
        """
        Crée un répertoire pour le site, génère un fichier de config .conf,
        active le site et recharge Apache.
        """
        print("[INFO] Configuration du service Apache2...")
        commandes = [
            f"sudo mkdir -p /var/www/html/{site_name}",
            f"echo '<h1>Bienvenue sur le site {site_name}</h1>' | sudo tee /var/www/html/{site_name}/index.html",
            (
                "sudo bash -c 'cat > /etc/apache2/sites-available/"
                f"{site_name}.conf <<EOF\n"
                f"<VirtualHost *:{port}>\n"
                f"    ServerAdmin webmaster@localhost\n"
                f"    DocumentRoot /var/www/html/{site_name}\n"
                f"    ErrorLog ${{APACHE_LOG_DIR}}/error.log\n"
                f"    CustomLog ${{APACHE_LOG_DIR}}/access.log combined\n"
                f"</VirtualHost>\n"
                f"EOF'"
            ),
            f"sudo a2ensite {site_name}",
            "sudo systemctl reload apache2"
        ]

        for cmd in commandes:
            output, error = self.execute_command(cmd)
            if error.strip():
                print(f"[ERREUR] : {error}")
            else:
                print(output)

    def list_apache_sites(self):
        """
        Liste les fichiers .conf dans /etc/apache2/sites-available
        pour déterminer les sites existants.
        """
        print("[INFO] Récupération des sites Apache disponibles...")
        output, error = self.execute_command("ls /etc/apache2/sites-available | grep '.conf'")
        if error.strip():
            print(f"[ERREUR] : {error}")
            return []
        else:
            sites = [line.replace('.conf', '') for line in output.splitlines()]
            return sites

    def print_web_configuration(self, site_name):
        """
        Affiche le contenu du fichier de configuration du site <site_name>.
        """
        print(f"[INFO] Affichage de la configuration pour le site : {site_name}")
        output, error = self.execute_command(f"sudo /bin/cat /etc/apache2/sites-available/{site_name}.conf")
        if error.strip():
            print(f"[ERREUR] : {error}")
        else:
            print(output)

    def delete_apache_site(self, site_name):
        """
        Désactive le site, supprime le fichier .conf et le dossier du site,
        puis recharge Apache.
        """
        print(f"[INFO] Suppression du site Apache : {site_name}...")
        commandes = [
            f"sudo a2dissite {site_name}",
            f"sudo rm -f /etc/apache2/sites-available/{site_name}.conf",
            f"sudo rm -rf /var/www/html/{site_name}",
            "sudo systemctl reload apache2"
        ]
        for cmd in commandes:
            output, error = self.execute_command(cmd)
            if error.strip():
                print(f"[ERREUR] lors de l'exécution de la commande : {cmd}\n{error}")
            else:
                print(output)


class FTPManager(SSHPackageManager):
    """
    Gère la configuration du serveur FTP (vsftpd).
    """

    def configure_vsftpd(self, anonymous_enable, local_enable, write_enable):
        """
        Sauvegarde le fichier /etc/vsftpd.conf, puis modifie les lignes
        anonymous_enable / local_enable / write_enable (même si elles sont commentées).
        Ensuite redémarre vsftpd.
        """
        print("[INFO] Configuration de vsftpd...")
        commandes = [
            "sudo cp /etc/vsftpd.conf /etc/vsftpd.conf.bak",
            f"sudo sed -i 's/^#\\?anonymous_enable=.*/anonymous_enable={anonymous_enable.upper()}/' /etc/vsftpd.conf",
            f"sudo sed -i 's/^#\\?local_enable=.*/local_enable={local_enable.upper()}/' /etc/vsftpd.conf",
            f"sudo sed -i 's/^#\\?write_enable=.*/write_enable={write_enable.upper()}/' /etc/vsftpd.conf",
            "sudo systemctl restart vsftpd"
        ]

        for cmd in commandes:
            output, error = self.execute_command(cmd)
            if error.strip():
                print(f"[ERREUR] : {error}")
            else:
                print(output)

    def print_ftp_configuration(self):
        """
        Affiche les lignes qui correspondent à (anonymous_enable|local_enable|write_enable)
        dans /etc/vsftpd.conf pour vérifier la config actuelle.
        """
        print("[INFO] Affichage des lignes modifiées dans la configuration FTP...")
        output, error = self.execute_command("sudo /usr/bin/grep -E '^(anonymous_enable|local_enable|write_enable)' /etc/vsftpd.conf")
        if error.strip():
            print(f"[ERREUR] : {error}")
        else:
            print(output)


class LDAPManager(SSHPackageManager):
    """
    Gère l'installation et la configuration d'OpenLDAP,
    ainsi que l'ajout et la liste d'utilisateurs dans l'annuaire.
    """

    def install_and_configure_ldap(self, domain="dc=example,dc=com", org_name="ExampleOrg", admin_password="admin"):
        """
        Installation et configuration non-interactive d'OpenLDAP.
        1) Définir les réponses Debconf (suffixe, mdp, backend...),
        2) Installer slapd + ldap-utils,
        3) Reconfigurer (dpkg-reconfigure) pour finaliser.
        """
        print("[INFO] Installation et configuration non-interactive d'OpenLDAP...")

        # 1) Définir toutes les sélections Debconf avant l’installation
        debconf_commands = [
            f"sudo debconf-set-selections <<< 'slapd slapd/password1 password {admin_password}'",
            f"sudo debconf-set-selections <<< 'slapd slapd/password2 password {admin_password}'",
            f"sudo debconf-set-selections <<< 'slapd slapd/domain string {domain.replace('dc=', '').replace(',dc=', '.')}'",
            f"sudo debconf-set-selections <<< 'slapd shared/organization string {org_name}'",
            f"sudo debconf-set-selections <<< 'slapd slapd/backend select mdb'",
            f"sudo debconf-set-selections <<< 'slapd slapd/purge_database boolean true'",
            f"sudo debconf-set-selections <<< 'slapd slapd/move_old_database boolean true'",
            f"sudo debconf-set-selections <<< 'slapd slapd/allow_ldap_v2 boolean false'"
        ]
        for cmd in debconf_commands:
            self.execute_command(cmd)

        # 2) Installer slapd et ldap-utils en mode non-interactif
        self.execute_command("sudo apt-get update")
        output, error = self.execute_command("sudo apt-get install -y slapd ldap-utils")
        if error.strip():
            print(f"[ERREUR] lors de l'installation d'OpenLDAP : {error}")
        else:
            print(output)

        # 3) (Optionnel) On peut refaire un dpkg-reconfigure pour être sûr
        #    que toutes les options sont bien appliquées
        reconfigure_output, reconfigure_err = self.execute_command(
            "sudo dpkg-reconfigure -f noninteractive slapd"
        )
        if reconfigure_err.strip():
            print(f"[ERREUR] lors de la configuration : {reconfigure_err}")
        else:
            print(reconfigure_output)

    def configure_ldap(self, domain="dc=example,dc=com", org_name="ExampleOrg", admin_password="admin"):
        """
        Configure slapd de manière non interactive,
        via debconf-set-selections et dpkg-reconfigure.
        """
        print("[INFO] Configuration d'OpenLDAP via dpkg-reconfigure (non-interactive).")

        debconf_commands = [
            f"sudo debconf-set-selections <<< 'slapd slapd/password1 password {admin_password}'",
            f"sudo debconf-set-selections <<< 'slapd slapd/password2 password {admin_password}'",
            f"sudo debconf-set-selections <<< 'slapd slapd/domain string {domain.replace('dc=', '').replace(',dc=', '.')}'",
            f"sudo debconf-set-selections <<< 'slapd shared/organization string {org_name}'",
            f"sudo debconf-set-selections <<< 'slapd slapd/backend select mdb'",
            f"sudo debconf-set-selections <<< 'slapd slapd/purge_database boolean true'",
            f"sudo debconf-set-selections <<< 'slapd slapd/move_old_database boolean true'",
            f"sudo debconf-set-selections <<< 'slapd slapd/allow_ldap_v2 boolean false'"
        ]
        for cmd in debconf_commands:
            self.execute_command(cmd)

        reconfigure_output, reconfigure_err = self.execute_command("sudo dpkg-reconfigure -f noninteractive slapd")
        if reconfigure_err.strip():
            print(f"[ERREUR] lors de la configuration : {reconfigure_err}")
        else:
            print(reconfigure_output)

    def add_ldap_user(self, user_cn, base_dn="dc=example,dc=com"):
        """
        Crée un utilisateur simple (inetOrgPerson) via un fichier LDIF temporaire,
        puis l'ajoute via ldapadd.
        """
        print(f"[INFO] Ajout de l'utilisateur {user_cn} dans le DN {base_dn}...")
        ldif_content = f"""
        dn: cn={user_cn},ou=People,{base_dn}
        objectClass: inetOrgPerson
        sn: {user_cn}
        cn: {user_cn}
        userPassword: secret
        """
        tmp_ldif_path = f"/tmp/{user_cn}.ldif"
        self.execute_command(f"echo \"{ldif_content}\" > {tmp_ldif_path}")

        output, error = self.execute_command(
            f"sudo ldapadd -x -D 'cn=admin,{base_dn}' -w admin -f {tmp_ldif_path}"
        )
        if error.strip():
            print(f"[ERREUR] lors de l'ajout de l'utilisateur LDAP : {error}")
        else:
            print(output)

    def list_ldap_users(self, base_dn="dc=example,dc=com"):
        """
        Fait un ldapsearch basique dans ou=People,
        et affiche le champ 'cn'.
        """
        print(f"[INFO] Listing des utilisateurs dans ou=People,{base_dn}...")
        output, error = self.execute_command(
            f"ldapsearch -x -LLL -b 'ou=People,{base_dn}' cn"
        )
        if error.strip():
            print(f"[ERREUR] lors du listing des utilisateurs : {error}")
        else:
            print(output)


class LinuxUserManager(SSHPackageManager):
    """
    Gère la création, suppression, modification de mot de passe
    et la liste des groupes utilisateurs sous Linux.
    """

    def create_user(self, username, password):
        print(f"[INFO] Création de l'utilisateur {username}.")
        # On vérifie si l'utilisateur existe déjà (id -u <username>)
        out, err = self.execute_command(f"id -u {username}")
        if "no such user" not in err.strip() and out.strip():
            print(f"[WARNING] L'utilisateur {username} existe déjà.")
            return

        # Création de l'utilisateur avec home directory (-m)
        create_out, create_err = self.execute_command(f"sudo useradd -m {username}")
        if create_err.strip():
            print(f"[ERREUR] Impossible de créer l'utilisateur : {create_err}")
            return
        else:
            print(create_out)

        # On définit le mot de passe via chpasswd
        passwd_out, passwd_err = self.execute_command(f"echo '{username}:{password}' | sudo chpasswd")
        if passwd_err.strip():
            print(f"[ERREUR] Impossible de changer le mot de passe : {passwd_err}")
        else:
            print("[INFO] Mot de passe défini avec succès.")

    def delete_user(self, username):
        print(f"[INFO] Suppression de l'utilisateur {username}.")
        out, err = self.execute_command(f"id -u {username}")
        if "no such user" in err.strip():
            print(f"[WARNING] L'utilisateur {username} n'existe pas.")
            return

        remove_out, remove_err = self.execute_command(f"sudo userdel -r {username}")
        if remove_err.strip():
            print(f"[ERREUR] lors de la suppression de l'utilisateur : {remove_err}")
        else:
            print(remove_out)

    def change_password(self, username, new_password):
        print(f"[INFO] Changement du mot de passe de {username}.")
        out, err = self.execute_command(f"id -u {username}")
        if "no such user" in err.strip():
            print(f"[WARNING] L'utilisateur {username} n'existe pas.")
            return

        passwd_out, passwd_err = self.execute_command(f"echo '{username}:{new_password}' | sudo chpasswd")
        if passwd_err.strip():
            print(f"[ERREUR] Impossible de changer le mot de passe : {passwd_err}")
        else:
            print("[INFO] Mot de passe modifié avec succès.")

    def list_groups(self, username):
        """
        Si un username est fourni, on liste ses groupes (id -nG <username>).
        Sinon, on liste tous les groupes (cut -d: -f1 /etc/group).
        """
        if username:
            print(f"[INFO] Groupes de {username} :")
            output, error = self.execute_command(f"id -nG {username}")
            if error.strip():
                print(f"[ERREUR] : {error}")
            else:
                print(output)
        else:
            print("[INFO] Liste de tous les groupes :")
            output, error = self.execute_command("cut -d: -f1 /etc/group")
            if error.strip():
                print(f"[ERREUR] : {error}")
            else:
                print(output)
