import paramiko
import os
import tempfile
import logging
import re
import ftplib

logger = logging.getLogger(__name__)


def domain_to_dn(domain: str) -> str:
    """
    Convertit un domaine (ex: 'example.com') en DN (ex: 'dc=example,dc=com').
    """
    parts = domain.split('.')
    dn_parts = [f"dc={p}" for p in parts]
    return ",".join(dn_parts)


class SSHPackageManager:
    """
    Classe de base qui gère la connexion SSH et propose des méthodes
    générales pour installer, supprimer, mettre à jour, vérifier des paquets.
    """

    def __init__(self, hostname, username, password):
        self.hostname = hostname
        self.username = username
        self.password = password

        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.client.connect(hostname, username=username, password=password)
            logger.info(f"Connexion SSH établie avec {hostname}.")
        except Exception as e:
            logger.exception(f"Erreur lors de la connexion SSH à {hostname}: {e}")

    def execute_command(self, command):
        """
        Exécute une commande sur la machine distante en forçant un environnement non-interactif.
        """
        command = f"export TERM=xterm DEBIAN_FRONTEND=noninteractive && {command}"
        try:
            stdin, stdout, stderr = self.client.exec_command(command)
            return stdout.read().decode(), stderr.read().decode()
        except Exception as e:
            logger.exception(f"Exception lors de l'exécution de la commande: {command}")
            return "", str(e)

    def run_command(self, command, success_message=None, print_output=True):
        """
        Exécute une commande via execute_command, gère et affiche les erreurs.
        Retourne la sortie standard en cas de succès, sinon None.
        """
        try:
            output, error = self.execute_command(command)
            if error.strip():
                logger.error(f"Erreur lors de l'exécution de '{command}': {error.strip()}")
                return None
            else:
                if success_message:
                    logger.info(success_message)
                elif print_output:
                    logger.info(output.strip())
                return output.strip()
        except Exception as e:
            logger.exception(f"Exception lors de l'exécution de la commande: {command}")
            return None

    def install_single_package(self, package):
        """
        Installe les paquets via sudo apt-get install -y <package>.
        """
        logger.info(f"[INFO] Installation du paquet {package}...")
        self.run_command(f"sudo apt-get install -y {package}",
                         success_message=f"[INFO] Installation du paquet {package} terminée.")

    def install_packages(self, package_name):
        """
        Installe plusieurs paquets en une seule commande.
        """
        packages = package_name.split()
        self.run_command("sudo apt-get update",
                         success_message="[INFO] Mise à jour de la liste des paquets terminée.")
        for package in packages:
            self.install_single_package(package)

    def remove_package(self, package_name):
        """
        Supprime un paquet via sudo apt-get remove -y <package>.
        """
        logger.info(f"[INFO] Suppression du paquet {package_name}...")
        self.run_command(f"sudo apt-get remove -y {package_name}",
                         success_message=f"[INFO] Suppression du paquet {package_name} terminée.")
        self.run_command("sudo apt-get autoremove -y",
                         success_message="[INFO] Nettoyage des paquets inutilisés terminé.")

    def verify_package(self, package_name):
        """
        Vérifie si un paquet est installé en utilisant dpkg -l.
        Retourne True si le paquet est installé, False sinon.
        """
        logger.info(f"[INFO] Vérification de l'installation de {package_name} avec dpkg...")
        output = self.run_command(f"dpkg -l | grep {package_name}", print_output=False)
        if output and output.strip():
            logger.info(f"[OK] Le paquet {package_name} est installé.")
            return True
        else:
            logger.info(f"[INFO] Le paquet {package_name} n'est pas installé.")
            return False

    def update_package(self, package_name):
        """
        Met à jour un paquet via sudo apt-get update && sudo apt-get install --only-upgrade -y <package>.
        """
        if self.verify_package(package_name):
            logger.info(f"[INFO] Mise à jour du paquet {package_name}...")
            self.run_command(f"sudo apt-get update && sudo apt-get install --only-upgrade -y {package_name}",
                             success_message=f"[INFO] Mise à jour du paquet {package_name} terminée.")
        else:
            logger.info(f"[INFO] Le paquet {package_name} n'est pas installé, aucune mise à jour nécessaire.")

    def close_connection(self):
        """
        Ferme la connexion SSH.
        """
        self.client.close()
        logger.info("[INFO] Connexion SSH fermée.")


class WebManager(SSHPackageManager):
    """
    Gère les actions spécifiques aux serveurs web (Apache2 ou Nginx).
    Lors de l'installation, si l'autre serveur est installé, il est supprimé pour éviter tout conflit.
    """

    def is_apache_installed(self):
        """
        Vérifie si Apache2 est installé en vérifiant la présence de /usr/sbin/apache2.
        """
        cmd = "[ -x /usr/sbin/apache2 ] && echo 'YES' || echo 'NO'"
        output = self.run_command(cmd, print_output=False)
        return output.strip() == "YES"

    def is_nginx_installed(self):
        """
        Vérifie si Nginx est installé en vérifiant la présence de /usr/sbin/nginx.
        """
        cmd = "[ -x /usr/sbin/nginx ] && echo 'YES' || echo 'NO'"
        output = self.run_command(cmd, print_output=False)
        return output.strip() == "YES"

    def install_apache(self):
        """
        Installe Apache2 + PHP après avoir supprimé Nginx s'il est installé.
        """
        if self.is_nginx_installed():
            logger.info("[INFO] Nginx est installé. Suppression avant l'installation d'Apache.")
            self.run_command("sudo systemctl stop nginx", success_message="[INFO] Nginx stoppé.")
            self.run_command("sudo apt-get remove --purge -y nginx", success_message="[INFO] Nginx supprimé.")
            self.run_command("sudo apt-get autoremove -y", success_message="[INFO] Nettoyage terminé.")
        self.install_packages("apache2 php8.2 libapache2-mod-php8.2")
        self.run_command("sudo systemctl start apache2", success_message="[INFO] Apache démarré.")
        self.run_command("sudo systemctl enable apache2", success_message="[INFO] Apache activé.")

    def install_nginx(self):
        """
        Installe Nginx après avoir supprimé Apache s'il est installé.
        """
        if self.is_apache_installed():
            logger.info("[INFO] Apache est installé. Suppression avant l'installation de Nginx.")
            self.run_command("sudo systemctl stop apache2", success_message="[INFO] Apache stoppé.")
            self.run_command("sudo apt-get remove --purge -y apache2", success_message="[INFO] Apache supprimé.")
            self.run_command("sudo apt-get autoremove -y", success_message="[INFO] Nettoyage terminé.")

        self.run_command("sudo apt-get update", success_message="[INFO] Mise à jour de la liste des paquets terminée.")
        self.run_command("sudo apt-get install -y nginx",
                         success_message="[INFO] Nginx installé.")
        # Démarrer et activer Nginx séparément
        self.run_command("sudo systemctl start nginx", success_message="[INFO] Nginx démarré.")
        self.run_command("sudo systemctl enable nginx", success_message="[INFO] Nginx activé.")

    # ----------------- Apache -----------------
    def create_site_apache(self, site_name, port=80):
        """
        Crée un site Apache avec un fichier index.html de bienvenue.
        """
        logger.info("[INFO] Configuration du site Apache...")
        self.run_command(f"sudo mkdir -p /var/www/html/{site_name}",
                         success_message=f"[INFO] Répertoire /var/www/html/{site_name} créé.")
        self.run_command(
            f"echo '<h1>Bienvenue sur le site {site_name}</h1>' | sudo tee /var/www/html/{site_name}/index.html",
            success_message=f"[INFO] Page d'accueil pour {site_name} créée."
        )
        config_cmd = (
            "sudo bash -c 'cat > /etc/apache2/sites-available/"
            f"{site_name}.conf <<EOF\n"
            f"<VirtualHost *:{port}>\n"
            f"    ServerAdmin webmaster@localhost\n"
            f"    DocumentRoot /var/www/html/{site_name}\n"
            f"    ErrorLog ${{APACHE_LOG_DIR}}/error.log\n"
            f"    CustomLog ${{APACHE_LOG_DIR}}/access.log combined\n"
            f"</VirtualHost>\n"
            f"EOF'"
        )
        self.run_command(config_cmd,
                         success_message=f"[INFO] Fichier de configuration pour {site_name} créé.")
        self.run_command(f"sudo a2ensite {site_name}",
                         success_message=f"[INFO] Site {site_name} activé.")
        self.run_command("sudo systemctl reload apache2",
                         success_message="[INFO] Apache rechargé.")

    def delete_site_apache(self, site_name):
        """
        Supprime un site Apache en désactivant le site, supprimant le fichier de configuration et le répertoire.
        """
        logger.info(f"[INFO] Suppression du site Apache : {site_name}...")
        self.run_command(f"sudo a2dissite {site_name}",
                         success_message=f"[INFO] Site {site_name} désactivé.")
        self.run_command(f"sudo rm -f /etc/apache2/sites-available/{site_name}.conf",
                         success_message="[INFO] Fichier de configuration supprimé.")
        self.run_command(f"sudo rm -rf /var/www/html/{site_name}",
                         success_message="[INFO] Répertoire du site supprimé.")
        self.run_command("sudo systemctl reload apache2",
                         success_message="[INFO] Apache rechargé.")

    def list_sites_apache(self):
        """
        Récupère la liste des sites Apache disponibles en listant les fichiers .conf dans /etc/apache2/sites-available.
        """
        logger.info("[INFO] Récupération des sites Apache disponibles...")
        output = self.run_command("ls /etc/apache2/sites-available | grep '.conf'", print_output=False)
        if output:
            return [line.replace('.conf', '') for line in output.splitlines()]
        return []

    def print_site_apache(self, site_name):
        """
        Affiche le contenu du fichier de configuration du site Apache.
        """
        logger.info(f"[INFO] Affichage de la configuration pour le site Apache : {site_name}")
        self.run_command(f"sudo cat /etc/apache2/sites-available/{site_name}.conf")

    # ----------------- Nginx -----------------
    def create_site_nginx(self, site_name, port=80):
        """
        Crée un site Nginx avec un fichier index.html de bienvenue.
        """
        logger.info("[INFO] Configuration du site Nginx...")
        self.run_command(f"sudo mkdir -p /var/www/html/{site_name}",
                         success_message=f"[INFO] Répertoire /var/www/html/{site_name} créé.")
        self.run_command(
            f"echo '<h1>Bienvenue sur le site {site_name}</h1>' | sudo tee /var/www/html/{site_name}/index.html",
            success_message=f"[INFO] Page d'accueil pour {site_name} créée."
        )
        config_cmd = (
            "sudo bash -c 'cat > /etc/nginx/sites-available/"
            f"{site_name} <<EOF\n"
            f"server {{\n"
            f"    listen {port};\n"
            f"    server_name {site_name};\n"
            f"    root /var/www/html/{site_name};\n"
            f"    index index.html;\n"
            f"}}\n"
            f"EOF'"
        )
        self.run_command(config_cmd,
                         success_message=f"[INFO] Fichier de configuration pour {site_name} créé.")
        self.run_command(f"sudo ln -sf /etc/nginx/sites-available/{site_name} /etc/nginx/sites-enabled/",
                         success_message=f"[INFO] Site {site_name} activé.")
        self.run_command("sudo systemctl reload nginx",
                         success_message="[INFO] Nginx rechargé.")

    def delete_site_nginx(self, site_name):
        """
        Supprime un site Nginx en supprimant le fichier de configuration et le répertoire.
        """
        logger.info(f"[INFO] Suppression du site Nginx : {site_name}...")
        self.run_command(f"sudo rm -f /etc/nginx/sites-available/{site_name}",
                         success_message="[INFO] Fichier de configuration supprimé.")
        self.run_command(f"sudo rm -f /etc/nginx/sites-enabled/{site_name}",
                         success_message="[INFO] Lien symbolique supprimé.")
        self.run_command(f"sudo rm -rf /var/www/html/{site_name}",
                         success_message="[INFO] Répertoire du site supprimé.")
        self.run_command("sudo systemctl reload nginx",
                         success_message="[INFO] Nginx rechargé.")

    def list_sites_nginx(self):
        """
        Récupère la liste des sites Nginx disponibles en listant les fichiers dans /etc/nginx/sites-available.
        """
        logger.info("[INFO] Récupération des sites Nginx disponibles...")
        output = self.run_command("ls /etc/nginx/sites-available", print_output=False)
        if output:
            return output.splitlines()
        return []

    def print_site_nginx(self, site_name):
        """
        Affiche le contenu du fichier de configuration du site Nginx.
        """
        logger.info(f"[INFO] Affichage de la configuration pour le site Nginx : {site_name}")
        self.run_command(f"sudo cat /etc/nginx/sites-available/{site_name}")

 

class FTPManager(SSHPackageManager):
    """
    Gère la configuration du serveur FTP (vsftpd)
    et ajoute des fonctions pour créer des dossiers et envoyer des fichiers via FTP.
    """

    def configure_vsftpd(self, anonymous_enable, local_enable, write_enable):
        """
        Configure vsftpd en modifiant le fichier /etc/vsftpd.conf.
        """
        logger.info("[INFO] Configuration de vsftpd...")
        self.run_command("sudo cp /etc/vsftpd.conf /etc/vsftpd.conf.bak",
                         success_message="[INFO] Sauvegarde du fichier vsftpd.conf effectuée.")
        self.run_command(f"sudo sed -i 's/^#\\?anonymous_enable=.*/anonymous_enable={anonymous_enable.upper()}/' /etc/vsftpd.conf",
                         success_message="[INFO] Configuration de anonymous_enable mise à jour.")
        self.run_command(f"sudo sed -i 's/^#\\?local_enable=.*/local_enable={local_enable.upper()}/' /etc/vsftpd.conf",
                         success_message="[INFO] Configuration de local_enable mise à jour.")
        self.run_command(f"sudo sed -i 's/^#\\?write_enable=.*/write_enable={write_enable.upper()}/' /etc/vsftpd.conf",
                         success_message="[INFO] Configuration de write_enable mise à jour.")
        self.run_command("sudo systemctl restart vsftpd",
                         success_message="[INFO] vsftpd redémarré.")

    def print_ftp_configuration(self):
        """
        Affiche les paramètres de configuration du serveur FTP (vsftpd).
        """
        logger.info("[INFO] Affichage de la configuration FTP...")
        self.run_command("sudo /usr/bin/grep -E '^(anonymous_enable|local_enable|write_enable)' /etc/vsftpd.conf")

    def create_ftp_directory(self, directory):
        """
        Crée un dossier (directory) sur le serveur FTP en utilisant ftplib.
        """
        logger.info(f"[INFO] Création du dossier {directory} via FTP.")
        try:
            with ftplib.FTP(self.hostname, self.username, self.password) as ftp:
                ftp.mkd(directory)
            logger.info(f"[INFO] Dossier '{directory}' créé avec succès.")
        except ftplib.all_errors as e:
            logger.error(f"[ERREUR] Impossible de créer le dossier '{directory}': {str(e)}")

    def store_ftp_file(self, local_path, remote_path):
        """
        Envoie (STOR) un fichier local vers le serveur FTP en utilisant ftplib.
        """
        logger.info(f"[INFO] Envoi du fichier '{local_path}' vers '{remote_path}'.")
        try:
            with ftplib.FTP(self.hostname, self.username, self.password) as ftp:
                with open(local_path, 'rb') as f:
                    ftp.storbinary(f"STOR {remote_path}", f)
            logger.info(f"[INFO] Fichier '{local_path}' envoyé avec succès vers '{remote_path}'.")
        except ftplib.all_errors as e:
            logger.error(f"[ERREUR] Échec de l'envoi du fichier : {str(e)}")


class LDAPManager(SSHPackageManager):
    """
    Gère l'installation, la configuration, la purge d'OpenLDAP,
    ainsi que l'ajout et la liste d'utilisateurs dans l'annuaire.
    """

    def install_and_configure_ldap_via_script(self, domain, org_name, admin_password):
        """
        Installe OpenLDAP via un script Bash non-interactif.
        """
        script_content = f"""#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive

echo "=== Script d'installation et de configuration OpenLDAP ==="
echo "Domaine LDAP : {domain}"
echo "Organisation : {org_name}"
echo "Mot de passe Admin : {admin_password}"

# Debconf selections
sudo debconf-set-selections <<< 'slapd slapd/no_configuration boolean false'
sudo debconf-set-selections <<< 'slapd slapd/internal/adminpw password {admin_password}'
sudo debconf-set-selections <<< 'slapd slapd/internal/generated_adminpw password {admin_password}'

sudo debconf-set-selections <<< 'slapd slapd/password1 password {admin_password}'
sudo debconf-set-selections <<< 'slapd slapd/password2 password {admin_password}'
sudo debconf-set-selections <<< 'slapd slapd/domain string {domain}'
sudo debconf-set-selections <<< 'slapd shared/organization string {org_name}'
sudo debconf-set-selections <<< 'slapd slapd/backend select mdb'
sudo debconf-set-selections <<< 'slapd slapd/purge_database boolean true'
sudo debconf-set-selections <<< 'slapd slapd/move_old_database boolean true'
sudo debconf-set-selections <<< 'slapd slapd/allow_ldap_v2 boolean false'

# Installation
sudo apt-get update
sudo apt-get install -y slapd ldap-utils

echo "=== Fin du script d'installation OpenLDAP ==="
"""
        
        """
        Crée un script Bash temporaire, le transfère sur le serveur distant,
        le rend exécutable, le convertit en format UNIX et l'exécute.
        """

        logger.info("[INFO] Création du script Bash...")
        with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.sh') as tmpfile:
            tmpfile.write(script_content)
            local_script_path = tmpfile.name

        logger.info(f"[INFO] Script Bash créé localement : {local_script_path}")

        """
        Transfère le script sur le serveur distant via SFTP et l'exécute.
        """
        remote_script_path = "/tmp/config_openldap.sh"
        sftp = self.client.open_sftp()
        sftp.put(local_script_path, remote_script_path)
        sftp.close()

        """
        Exécute le script sur le serveur distant.
        Vérifie si le script a réussi à installer OpenLDAP.
        """
        self.run_command(f"sudo chmod +x {remote_script_path}",
                         success_message=f"[INFO] Permissions modifiées pour {remote_script_path}.")
        self.run_command(f"sudo dos2unix {remote_script_path}",
                         success_message=f"[INFO] Conversion du script {remote_script_path} effectuée.")
        self.run_command(f"ls -l {remote_script_path}")
        self.run_command("ls -l /tmp")
        self.run_command(f"sudo /bin/bash {remote_script_path}",
                         success_message="[INFO] Script d'installation OpenLDAP exécuté.")
        os.remove(local_script_path)

        """
        Crée une OU 'People' après l'installation d'OpenLDAP.
        """
        base_dn = domain_to_dn(domain)
        create_ou_cmd = f"""echo "dn: ou=People,{base_dn}
objectClass: organizationalUnit
ou: People" | sudo ldapadd -x -D 'cn=admin,{base_dn}' -w {admin_password}"""
        self.run_command(create_ou_cmd,
                         success_message="[INFO] OU People créée avec succès.")

        logger.info("[INFO] Script d'installation LDAP exécuté avec succès (ou erreurs signalées ci-dessus).")

    def configure_ldap(self, domain, org_name, admin_password):
        """
        Configure OpenLDAP via dpkg-reconfigure (non-interactif).
        """
        logger.info("[INFO] Configuration d'OpenLDAP via dpkg-reconfigure (non-interactive).")
        debconf_cmds = [
            f"sudo debconf-set-selections <<< 'slapd slapd/password1 password {admin_password}'",
            f"sudo debconf-set-selections <<< 'slapd slapd/password2 password {admin_password}'",
            f"sudo debconf-set-selections <<< 'slapd slapd/domain string {domain}'",
            f"sudo debconf-set-selections <<< 'slapd shared/organization string {org_name}'",
            f"sudo debconf-set-selections <<< 'slapd slapd/backend select mdb'",
            f"sudo debconf-set-selections <<< 'slapd slapd/purge_database boolean true'",
            f"sudo debconf-set-selections <<< 'slapd slapd/move_old_database boolean true'",
            f"sudo debconf-set-selections <<< 'slapd slapd/allow_ldap_v2 boolean false'"
        ]
        for cmd in debconf_cmds:
            self.run_command(cmd)
        self.run_command("sudo dpkg-reconfigure -f noninteractive slapd",
                         success_message="[INFO] Configuration d'OpenLDAP terminée.")

        base_dn = domain_to_dn(domain)
        create_ou_cmd = f"""echo "dn: ou=People,{base_dn}
objectClass: organizationalUnit
ou: People" | sudo ldapadd -x -D 'cn=admin,{base_dn}' -w {admin_password}"""
        self.run_command(create_ou_cmd,
                         success_message="[INFO] OU People créée avec succès après reconfiguration.")

    def add_ldap_user(self, user_cn, domain):
        """
        Ajoute un utilisateur LDAP à l'annuaire.
        """
        base_dn = domain_to_dn(domain)
        logger.info(f"[INFO] Ajout de l'utilisateur {user_cn} dans {base_dn}...")

        ldif_content = f"""
dn: cn={user_cn},ou=People,{base_dn}
objectClass: inetOrgPerson
sn: {user_cn}
cn: {user_cn}
userPassword: secret
"""
        tmp_ldif_path = f"/tmp/{user_cn}.ldif"
        self.run_command(f"echo \"{ldif_content}\" > {tmp_ldif_path}",
                         success_message=f"[INFO] Fichier LDIF pour {user_cn} créé.")
        self.run_command(f"sudo ldapadd -x -D 'cn=admin,{base_dn}' -w admin -f {tmp_ldif_path}",
                         success_message=f"[INFO] Utilisateur LDAP {user_cn} ajouté.")

    def delete_ldap_user(self, user_cn, domain, admin_password):
        """
        Supprime un utilisateur LDAP de l'annuaire.
        """
        base_dn = domain_to_dn(domain)
        dn = f"cn={user_cn},ou=People,{base_dn}"
        delete_cmd = f"sudo ldapdelete -x -D 'cn=admin,{base_dn}' -w {admin_password} '{dn}'"
        self.run_command(delete_cmd,
                         success_message=f"[INFO] Utilisateur {user_cn} supprimé avec succès.")

    def add_ou(self, ou_name, domain, admin_password):
        """
        Ajoute une unité d'organisation (OU) à l'annuaire LDAP.
        """
        base_dn = domain_to_dn(domain)
        add_ou_cmd = f"""echo "dn: ou={ou_name},{base_dn}
objectClass: organizationalUnit
ou: {ou_name}" | sudo ldapadd -x -D 'cn=admin,{base_dn}' -w {admin_password}"""
        self.run_command(add_ou_cmd,
                         success_message=f"[INFO] OU {ou_name} créée avec succès.")

    def remove_ou(self, ou_name, domain, admin_password):
        """
        Supprime une unité d'organisation (OU) de l'annuaire LDAP.
        """
        base_dn = domain_to_dn(domain)
        delete_ou_cmd = f"sudo ldapdelete -x -D 'cn=admin,{base_dn}' -w {admin_password} 'ou={ou_name},{base_dn}'"
        self.run_command(delete_ou_cmd,
                         success_message=f"[INFO] OU {ou_name} supprimée avec succès.")

    def list_ous(self, domain="example.com"):
        """
        Liste les unités d'organisation (OU) sous le domaine spécifié.
        """
        base_dn = domain_to_dn(domain)
        logger.info(f"[INFO] Listing des OU sous {base_dn}...")
        self.run_command(f"ldapsearch -x -LLL -b '{base_dn}' '(&(objectClass=organizationalUnit)(ou=*))' ou")

    def list_ldap_users(self, domain="example.com"):
        """
        Liste les utilisateurs sous le domaine spécifié dans 'ou=People'.
        """
        base_dn = domain_to_dn(domain)
        logger.info(f"[INFO] Listing des utilisateurs sous 'ou=People,{base_dn}'...")
        self.run_command(f"ldapsearch -x -LLL -b 'ou=People,{base_dn}' cn")

    def remove_ldap_config(self):
        """
        Supprime la configuration OpenLDAP (purge).
        """
        logger.info("[INFO] Suppression/Purge de la configuration OpenLDAP...")
        self.run_command("sudo apt-get remove --purge -y slapd",
                         success_message="[INFO] Package slapd purgé.")
        self.run_command("sudo rm -rf /etc/ldap/slapd.d /var/lib/ldap",
                         success_message="[INFO] Dossiers de configuration supprimés.")
        self.run_command("sudo apt-get autoremove -y",
                         success_message="[INFO] Nettoyage des paquets inutilisés terminé.")
        logger.info("[INFO] Configuration OpenLDAP supprimée (purge) avec succès.")

class LinuxUserManager(SSHPackageManager):
    """
    Gère la création, suppression, modification de mot de passe et la gestion des groupes utilisateurs.
    """

    def create_user(self, username, password):
        """
        Crée un utilisateur avec son mot de passe.
        """
        logger.info(f"[INFO] Création de l'utilisateur {username}.")
        output = self.run_command(f"id -u {username}", print_output=False)
        if output and "no such user" not in output:
            logger.warning(f"[WARNING] L'utilisateur {username} existe déjà.")
            return
        self.run_command(f"sudo useradd -m {username}",
                         success_message=f"[INFO] Utilisateur {username} créé.")
        self.run_command(f"echo '{username}:{password}' | sudo chpasswd",
                         success_message="[INFO] Mot de passe défini avec succès.")

    def delete_user(self, username):
        """
        Supprime un utilisateur.
        """
        logger.info(f"[INFO] Suppression de l'utilisateur {username}.")
        output = self.run_command(f"id -u {username}", print_output=False)
        if output is None:
            logger.warning(f"[WARNING] L'utilisateur {username} n'existe pas.")
            return
        self.run_command(f"sudo userdel -r {username}",
                         success_message=f"[INFO] Utilisateur {username} supprimé.")

    def change_password(self, username, new_password):
        logger.info(f"[INFO] Changement du mot de passe de {username}.")
        output = self.run_command(f"id -u {username}", print_output=False)
        if output is None:
            logger.warning(f"[WARNING] L'utilisateur {username} n'existe pas.")
            return
        self.run_command(f"echo '{username}:{new_password}' | sudo chpasswd",
                         success_message="[INFO] Mot de passe modifié avec succès.")

    def add_group_user(self, username, group_name):
        """
        Ajoute un utilisateur à un groupe.
        """
        logger.info(f"[INFO] Ajout de l'utilisateur {username} au groupe {group_name}.")
        # Créer le groupe s'il n'existe pas (-f: force, ignore l'erreur si déjà existant)
        self.run_command(f"sudo groupadd -f {group_name}",
                        success_message=f"[INFO] Groupe {group_name} créé (ou déjà existant).")
        # Ajouter l'utilisateur au groupe
        self.run_command(f"sudo usermod -aG {group_name} {username}",
                        success_message=f"[INFO] Utilisateur {username} ajouté au groupe {group_name}.")

    def del_group_user(self, username, group_name):
        """
        Retire un utilisateur d'un groupe.
        """
        logger.info(f"[INFO] Retrait de l'utilisateur {username} du groupe {group_name}.")
        # Retirer l'utilisateur du groupe
        self.run_command(f"sudo gpasswd -d {username} {group_name}",
                        success_message=f"[INFO] Utilisateur {username} retiré du groupe {group_name}.")
        # Supprimer le groupe s'il est vide
        self.run_command(f"sudo getent group {group_name} | grep -q : || sudo groupdel {group_name}",
                            success_message=f"[INFO] Groupe {group_name} supprimé s'il est vide.")
        # Supprimer les groupes vides
        self.run_command("find /etc/group -type f -empty -delete"
                        " && find /etc/gshadow -type f -empty -delete"
                        , success_message=f"[INFO] Groupes vides supprimés.")

    def list_groups(self, username):
        """
        Affiche les groupes de l'utilisateur spécifié.
        Si aucun utilisateur n'est spécifié, affiche tous les groupes.
        """
        if username:
            logger.info(f"[INFO] Groupes de {username} :")
            self.run_command(f"id -nG {username}")
        else:
            logger.info("[INFO] Liste de tous les groupes :")
            self.run_command("cut -d: -f1 /etc/group")

    def list_users(self):
        """
        Affiche la liste des utilisateurs.
        """

        logger.info("[INFO] Liste des utilisateurs :")
        self.run_command("cut -d: -f1 /etc/passwd")



class NetworkManager(SSHPackageManager):
    """
    Gère les configurations réseau et la configuration du DNS.
    """

    # def list_interfaces(self):
    #     logger.info("[INFO] Récupération des interfaces réseau...")
    #     self.run_command("ip link show")
    def list_interfaces_details(self):
        """
        Parcourt la sortie de 'ip addr show' pour trouver chaque interface
        et son adresse IPv4 (si elle existe), puis l'affiche.
        """
        output = self.run_command("ip addr show", print_output=False)
        if not output:
            logger.warning("[WARNING] Impossible de récupérer la liste des interfaces.")
            return

        interfaces = {}
        current_interface = None

        # Parcours ligne par ligne de la sortie
        for line in output.splitlines():
            # Si la ligne commence par "X: nom_interface:"
            header_match = re.match(r'^\d+:\s+(\S+):', line)
            if header_match:
                current_interface = header_match.group(1)
                interfaces[current_interface] = None  # Pas d'IP pour l'instant
            else:
                # On cherche une éventuelle IPv4
                if current_interface:
                    inet_match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', line)
                    if inet_match:
                        interfaces[current_interface] = inet_match.group(1)

        # Affichage
        for iface, ip in interfaces.items():
            if ip:
                print(f"{iface}: {ip}")
            else:
                print(f"{iface}: Aucun IP assignée")

    def get_interface_status(self, interface):
        """
        Retourne True si l'interface est UP, False si elle est DOWN ou inexistante.
        """
        logger.info(f"[INFO] Vérification de l'état de l'interface {interface}...")
        # On utilise 'ip -br link show' qui donne un format concis
        output = self.run_command(f"ip -br link show {interface}", print_output=False)

        if not output:
            logger.info(f"[INFO] Impossible de récupérer l'état de '{interface}' (peut-être inexistante).")
            return False

        # Exemple de ligne : "ens36   UP   00:0c:29:76:50:42 <BROADCAST,MULTICAST,UP,LOWER_UP>"
        # On split pour extraire le nom et l'état
        lines = output.strip().splitlines()
        for line in lines:
            columns = line.split()
            # columns[0] = nom d'interface, columns[1] = état (UP, DOWN, UNKNOWN, etc.)
            if len(columns) >= 2 and columns[0] == interface:
                state = columns[1].upper()
                return (state == "UP")

        return False

    def enable_interface(self, interface):
        """
        Active une interface réseau si elle est DOWN. Sinon, ne fait rien.
        """
        logger.info(f"[INFO] Activation de l'interface {interface}...")

        # On regarde si l'interface est déjà UP
        if self.get_interface_status(interface):
            logger.info(f"[INFO] L'interface {interface} est déjà UP. Aucune action nécessaire.")
            return

        # Sinon, on l'active
        self.run_command(f"sudo ip link set {interface} up",
                         success_message=f"[INFO] Interface {interface} activée.")
        self.run_command(f"ip -br link show {interface}")
        self.list_interfaces_details()

    def disable_interface(self, interface):
        """
        Désactive une interface réseau si elle est UP. Sinon, ne fait rien.
        """
        logger.info(f"[INFO] Désactivation de l'interface {interface}...")

        # On regarde si l'interface est UP
        if not self.get_interface_status(interface):
            logger.info(f"[INFO] L'interface {interface} est déjà DOWN ou inexistante.")
            return

        # Sinon, on la désactive
        self.run_command(f"sudo ip link set {interface} down",
                         success_message=f"[INFO] Interface {interface} désactivée.")
        self.run_command(f"ip -br link show {interface}")

    def configure_static_ip(self, interface, ip, netmask, gateway):
        """
        Configure une adresse IP statique pour l'interface réseau spécifiée.
        """
        logger.info(f"[INFO] Configuration de l'IP statique sur {interface}...")
        self.run_command(f"sudo ip addr flush dev {interface}",
                         success_message=f"[INFO] Configuration IP de {interface} réinitialisée.")
        prefix = self.netmask_to_prefix(netmask)
        self.run_command(f"sudo ip addr add {ip}/{prefix} dev {interface}",
                         success_message=f"[INFO] {interface} configurée avec l'IP {ip}/{prefix}.")
        self.run_command(f"sudo ip route add default via {gateway} dev {interface}",
                         success_message=f"[INFO] Route par défaut configurée via {gateway}.")
        self.list_interfaces_details()
        self.run_command("ip route show")

    def configure_dhcp(self, interface):
        """
        Configure l'interface réseau spécifiée pour obtenir une adresse IP via DHCP.
        """
        logger.info(f"[INFO] Configuration DHCP pour l'interface {interface}...")
        self.run_command(f"sudo dhclient {interface}",
                         success_message=f"[INFO] Configuration DHCP pour {interface} terminée.")
        self.list_interfaces_details()
    
    def list_dhcp_leases(self):
        """
        Affiche les baux DHCP actifs.
        """
        logger.info("[INFO] Liste des baux DHCP actifs...")
        self.run_command("cat /var/lib/dhcp/dhclient.leases")
        logger.info("[INFO] Liste des baux DHCP actifs :")
        self.list_interfaces_details()

    def reset_dns(self):
        """
        Réinitialise le DNS.
        Supprime le fichier /etc/resolv.conf et configure le DNS avec Google Public DNS.
        """
        logger.info("[INFO] Réinitialisation du DNS...")
        self.run_command("sudo rm /etc/resolv.conf",
                         success_message="[INFO] Fichier /etc/resolv.conf réinitialisé.")
        self.run_command("sudo echo 'nameserver 8.8.8.8' | sudo tee /etc/resolv.conf",
                         success_message="[INFO] DNS réinitialisé avec Google Public DNS.")
        self.run_command("cat /etc/resolv.conf")
        logger.info("[INFO] DNS réinitialisé avec Google Public DNS.")
    
    def list_dns(self):
        """
        Affiche les serveurs DNS actuels.
        """
        logger.info("[INFO] Récupération des serveurs DNS actuels...")
        self.run_command("cat /etc/resolv.conf")
        logger.info("[INFO] Serveurs DNS actuels :")

    def netmask_to_prefix(self, netmask):
        """
        Convertit un masque de sous-réseau en notation CIDR.
        """
        return sum(bin(int(octet)).count("1") for octet in netmask.split("."))

    def set_dns(self, primary_dns, secondary_dns=None):
        """
        Configure le DNS avec les serveurs spécifiés.
        """
        logger.info("[INFO] Configuration du DNS...")
        resolv_content = f"nameserver {primary_dns}\n"
        if secondary_dns:
            resolv_content += f"nameserver {secondary_dns}\n"
        command = f"echo '{resolv_content}' | sudo tee /etc/resolv.conf"
        self.run_command(command,
                         success_message=f"[INFO] DNS configuré avec {primary_dns}" + (f" et {secondary_dns}" if secondary_dns else "") + ".")
        self.run_command("cat /etc/resolv.conf")
