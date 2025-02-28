import paramiko
import os
from getpass import getpass
import logging
import sys
from colored_formatter import ColoredFormatter

"""
Ce script permet de gérer un serveur distant via SSH.
Il propose un menu interactif pour gérer les paquets, le serveur web, le serveur FTP, le serveur LDAP, les utilisateurs Linux et le réseau.
Les actions sont effectuées sur le serveur distant via SSH.
Vous pouvez ajouter vos propres commandes en créant une nouvelle classe dans le fichier classes.py.
"""

# Configuration des logs
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(ColoredFormatter("%(asctime)s - %(levelname)s - %(message)s"))
logging.basicConfig(level=logging.INFO, handlers=[handler])
logger = logging.getLogger(__name__)

def clear_screen():
    """
    Efface l'écran de la console.
    """
    os.system("cls" if os.name == "nt" else "clear")

def menu_print(message, level="INFO"):
    """
    Affiche un message coloré dans la console.
    """
    color = ColoredFormatter.COLORS.get(level, ColoredFormatter.RESET)
    print(f"{color}{message}{ColoredFormatter.RESET}")

def display_menu(options):
    """
    Affiche dynamiquement une liste d'options et retourne le numéro choisi.
    """
    for idx, opt in enumerate(options, start=1):
        menu_print(f"{idx}. {opt}", level="INFO")
    choice = input("Sélectionnez une option : ")
    try:
        num = int(choice)
        if 1 <= num <= len(options):
            return num
        else:
            logger.error("Choix invalide.")
            return None
    except ValueError:
        logger.error("Entrée non numérique.")
        return None

from classes import (
    SSHPackageManager,
    WebManager,
    FTPManager,
    LDAPManager,
    LinuxUserManager,
    NetworkManager
)

def authenticate_remote(hostname):
    """
    Authentification SSH avec l'utilisateur et mot de passe fournis.
    Vérifie si l'utilisateur est administrateur (sudo).
    """
    logger.info("[AUTH] Authentification requise...")
    user = input("Nom d'utilisateur SSH : ")
    password = getpass("Mot de passe SSH : ")
    temp_client = paramiko.SSHClient()
    temp_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        temp_client.connect(hostname, username=user, password=password)
    except Exception as e:
        logger.error(f"[ERREUR] Échec de la connexion SSH : {str(e)}")
        return None, None, False
    try:
        stdin, stdout, stderr = temp_client.exec_command(f"id -nG {user}")
        groups = stdout.read().decode().strip().split()
    except Exception as e:
        logger.error(f"[ERREUR] Échec de l'exécution de la commande d'identification : {str(e)}")
        groups = []
    finally:
        temp_client.close()
    is_admin = ('sudo' in groups) or ('admin' in groups)
    return user, password, is_admin

def package_menu(package_manager, is_admin):
    """
    Menu de gestion des paquets.
    """
    while True:
        clear_screen()
        options = []
        # Si l'utilisateur est admin il peux installer, desinstaller et mettre a jour les paquets
        # Sinon, il peut seulement verifier l'installation d'un paquet
        if is_admin:
            options.extend([
                "Installer des paquets",
                "Désinstaller un paquet",
                "Mettre à jour un paquet"
            ])
        options.append("Vérifier l'installation d'un paquet")
        options.append("Retour au menu principal")
        num = display_menu(options)
        if num is None:
            input("Appuyez sur Entrée pour continuer...")
            continue
        if is_admin:
            if num == 1:
                packages = input("Entrez les paquets à installer (séparés par des espaces) : ")
                package_manager.install_packages(packages)
            elif num == 2:
                package = input("Entrez le nom du paquet à désinstaller : ")
                package_manager.remove_package(package)
            elif num == 3:
                package = input("Entrez le nom du paquet à mettre à jour : ")
                package_manager.update_package(package)
            elif num == 4:
                package = input("Entrez le nom du paquet à vérifier : ")
                package_manager.verify_package(package)
            elif num == 5:
                break
        else:
            if num == 1:
                package = input("Entrez le nom du paquet à vérifier : ")
                package_manager.verify_package(package)
            elif num == 2:
                break
        input("Appuyez sur Entrée pour continuer...")


def web_menu(web_manager, is_admin):
    """
    Menu de gestion du serveur web.
    """
    while True:
        clear_screen()
        options = []
        # Si l'utilisateur est admin, il peut installer un serveur web, configurer un site, supprimer un site.
        # Sinon, il peut seulement afficher la configuration d'un site.
        if is_admin:
            options.extend([
                "Installer un serveur web (Apache ou Nginx)",
                "Configurer un site web",
                "Supprimer un site web"
            ])
        options.append("Afficher la configuration d'un site web")
        options.append("Retour au menu principal")
        num = display_menu(options)
        if num is None:
            input("Appuyez sur Entrée pour continuer...")
            continue

        if is_admin:
            if num == 1:
                srv = input("Choisissez le serveur à installer (A pour Apache, N pour Nginx) : ").strip().upper()
                if srv == "A":
                    web_manager.install_apache()
                    menu_print("[INFO] Apache installé.", level="INFO")
                elif srv == "N":
                    web_manager.install_nginx()
                    menu_print("[INFO] Nginx installé.", level="INFO")
                else:
                    logger.error("[ERREUR] Choix invalide (A/N).")
            elif num == 2:
                srv = input("Serveur (A pour Apache, N pour Nginx) : ").strip().upper()
                if srv not in ["A", "N"]:
                    logger.error("[ERREUR] Choix invalide (A/N).")
                    continue
                # Vérification d'installation
                if srv == "A" and not web_manager.is_apache_installed():
                    logger.error("[ERREUR] Apache n'est pas installé.")
                    continue
                if srv == "N" and not web_manager.is_nginx_installed():
                    logger.error("[ERREUR] Nginx n'est pas installé.")
                    continue
                site_name = input("Nom du site : ")
                port_str = input("Port (défaut 80) : ")
                try:
                    port = int(port_str) if port_str.strip() else 80
                except ValueError:
                    logger.error("[ERREUR] Port invalide, utilisation de 80.")
                    port = 80
                if srv == "A":
                    web_manager.create_site_apache(site_name, port)
                else:
                    web_manager.create_site_nginx(site_name, port)
            elif num == 3:
                srv = input("Serveur (A pour Apache, N pour Nginx) : ").strip().upper()
                if srv not in ["A", "N"]:
                    logger.error("[ERREUR] Choix invalide (A/N).")
                    continue
                if srv == "A":
                    if not web_manager.is_apache_installed():
                        logger.error("[ERREUR] Apache n'est pas installé.")
                        continue
                    sites = web_manager.list_sites_apache()
                else:
                    if not web_manager.is_nginx_installed():
                        logger.error("[ERREUR] Nginx n'est pas installé.")
                        continue
                    sites = web_manager.list_sites_nginx()
                if not sites:
                    menu_print("[INFO] Aucun site trouvé.", level="INFO")
                    continue
                menu_print("Sites disponibles :", level="INFO")
                for idx, s in enumerate(sites, start=1):
                    menu_print(f"{idx}. {s}", level="INFO")
                try:
                    sel = int(input("Sélectionnez le site à supprimer : ")) - 1
                    if 0 <= sel < len(sites):
                        confirm = input(f"Supprimer '{sites[sel]}' ? (yes/no) : ").lower()
                        if confirm == "yes":
                            if srv == "A":
                                web_manager.delete_site_apache(sites[sel])
                            else:
                                web_manager.delete_site_nginx(sites[sel])
                            menu_print("[INFO] Site supprimé.", level="INFO")
                        else:
                            menu_print("[INFO] Suppression annulée.", level="INFO")
                    else:
                        logger.error("[ERREUR] Choix invalide.")
                except ValueError:
                    logger.error("[ERREUR] Entrée non numérique.")
            elif num == 4:
                srv = input("Serveur (A pour Apache, N pour Nginx) : ").strip().upper()
                if srv not in ["A", "N"]:
                    logger.error("[ERREUR] Choix invalide (A/N).")
                    continue
                if srv == "A":
                    if not web_manager.is_apache_installed():
                        logger.error("[ERREUR] Apache n'est pas installé.")
                        continue
                    sites = web_manager.list_sites_apache()
                else:
                    if not web_manager.is_nginx_installed():
                        logger.error("[ERREUR] Nginx n'est pas installé.")
                        continue
                    sites = web_manager.list_sites_nginx()
                if not sites:
                    menu_print("[INFO] Aucun site trouvé.", level="INFO")
                    continue
                menu_print("Sites disponibles :", level="INFO")
                for idx, s in enumerate(sites, start=1):
                    menu_print(f"{idx}. {s}", level="INFO")
                try:
                    sel = int(input("Sélectionnez le site à afficher : ")) - 1
                    if 0 <= sel < len(sites):
                        if srv == "A":
                            web_manager.print_site_apache(sites[sel])
                        else:
                            web_manager.print_site_nginx(sites[sel])
                    else:
                        logger.error("[ERREUR] Choix invalide.")
                except ValueError:
                    logger.error("[ERREUR] Entrée non numérique.")
            elif num == 5:
                break
        else:
            options_non_admin = [
                "Afficher la configuration d'un site web",
                "Retour au menu principal"
            ]
            num = display_menu(options_non_admin)
            if num is None:
                input("Appuyez sur Entrée pour continuer...")
                continue
            if num == 1:
                srv = input("Serveur (A pour Apache, N pour Nginx) : ").strip().upper()
                if srv not in ["A", "N"]:
                    logger.error("[ERREUR] Choix invalide (A/N).")
                    continue
                if srv == "A":
                    if not web_manager.is_apache_installed():
                        logger.error("[ERREUR] Apache n'est pas installé.")
                        continue
                    sites = web_manager.list_sites_apache()
                else:
                    if not web_manager.is_nginx_installed():
                        logger.error("[ERREUR] Nginx n'est pas installé.")
                        continue
                    sites = web_manager.list_sites_nginx()
                if not sites:
                    menu_print("[INFO] Aucun site trouvé.", level="INFO")
                    continue
                menu_print("Sites disponibles :", level="INFO")
                for idx, s in enumerate(sites, start=1):
                    menu_print(f"{idx}. {s}", level="INFO")
                try:
                    sel = int(input("Sélectionnez le site à afficher : ")) - 1
                    if 0 <= sel < len(sites):
                        if srv == "A":
                            web_manager.print_site_apache(sites[sel])
                        else:
                            web_manager.print_site_nginx(sites[sel])
                    else:
                        logger.error("[ERREUR] Choix invalide.")
                except ValueError:
                    logger.error("[ERREUR] Entrée non numérique.")
            elif num == 2:
                break
        input("Appuyez sur Entrée pour continuer...")

def ftp_menu(ftp_manager, is_admin):
    while True:
        clear_screen()
        options = []
        # Si l'utilisateur est admin il peux installer, configurer et gérer le serveur FTP
        # Sinon, il peut seulement afficher la configuration FTP
        if is_admin:
            options.extend([
                "Installer le serveur FTP (vsftpd)",
                "Configurer le serveur FTP/SFTP",
                "Créer un dossier sur le serveur FTP",
                "Envoyer un fichier sur le serveur FTP"
            ])
        options.append("Afficher la configuration FTP")
        options.append("Retour au menu principal")
        num = display_menu(options)
        if num is None:
            input("Appuyez sur Entrée pour continuer...")
            continue
        if is_admin:
            if num == 1:
                ftp_manager.install_single_package("vsftpd")
            elif num == 2:
                menu_print("\nConfiguration du serveur FTP/SFTP :", level="INFO")
                mode = input("Choisissez le mode (F pour FTP, S pour SFTP) : ").strip().upper()
                anonymous_enable = input("Autoriser les connexions anonymes ? (yes/no) : ").strip().lower()
                local_enable = input("Autoriser les utilisateurs locaux ? (yes/no) : ").strip().lower()
                write_enable = input("Autoriser les écritures (upload) ? (yes/no) : ").strip().lower()
                if mode == "F":
                    port = input("Entrez le port FTP désiré (par défaut 21) : ").strip()
                    if not port:
                        port = "21"
                    elif not port.isdigit():
                        logger.error("[ERREUR] Le port doit être un nombre.")
                        input("Appuyez sur Entrée pour continuer...")
                        continue
                    ftp_manager.configure_vsftpd(anonymous_enable, local_enable, write_enable, port)
                elif mode == "S":
                    menu_print("[INFO] En mode SFTP, le port reste par défaut (22).", level="INFO")
                    ftp_manager.configure_vsftpd(anonymous_enable, local_enable, write_enable)
                else:
                    logger.error("[ERREUR] Mode invalide.")
            elif num == 3:
                directory = input("Entrez le chemin du dossier à créer (ex: /nouveau_dossier) : ")
                ftp_manager.create_ftp_directory(directory)
            elif num == 4:
                local_path = input("Chemin local du fichier à envoyer (ex: /home/user/fichier.txt) : ")
                remote_path = input("Chemin distant (ex: /upload/fichier.txt) : ")
                ftp_manager.store_ftp_file(local_path, remote_path)
            elif num == 5:
                ftp_manager.print_ftp_configuration()
            elif num == 6:
                break
        else:
            # Pour non-admin, seules les options d'affichage et retour sont disponibles.
            if num == 1:
                ftp_manager.print_ftp_configuration()
            elif num == 2:
                break
        input("Appuyez sur Entrée pour continuer...")

def ldap_menu(ldap_manager, is_admin):
    while True:
        clear_screen()
        options = []
        # Si l'utilisateur est admin il peut installer, configurer et gérer OpenLDAP
        # Sinon, il peut seulement lister les utilisateurs LDAP
        if is_admin:
            options.extend([
                "Installer & configurer OpenLDAP (non-interactif)",
                "Reconfigurer OpenLDAP (changer domaine, org, mot de passe)",
                "Ajouter un utilisateur LDAP",
                "Lister les utilisateurs LDAP",
                "Supprimer la configuration OpenLDAP",
                "Supprimer un utilisateur LDAP",
                "Ajouter une OU",
                "Supprimer une OU",
                "Lister les OU"
            ])
        options.append("Retour au menu principal")
        num = display_menu(options)
        if num is None:
            input("Appuyez sur Entrée pour continuer...")
            continue
        if is_admin:
            if num == 1:
                domain = input("Entrez le nom de domaine LDAP (ex: example.com) : ").strip() or "example.com"
                org = input("Entrez le nom de l'organisation (ex: ExampleOrg) : ").strip() or "ExampleOrg"
                admin_pass = getpass("Entrez le mot de passe admin LDAP : ").strip() or "admin"
                ldap_manager.install_and_configure_ldap_via_script(domain, org, admin_pass)
            elif num == 2:
                domain = input("Entrez le nouveau domaine LDAP (ex: example.com) : ").strip() or "example.com"
                org = input("Entrez le nouveau nom de l'organisation (ex: ExampleOrg) : ").strip() or "ExampleOrg"
                admin_pass = getpass("Entrez le nouveau mot de passe admin LDAP : ").strip() or "admin"
                ldap_manager.configure_ldap(domain, org, admin_pass)
            elif num == 3:
                user_cn = input("Nom (cn) de l'utilisateur à ajouter : ").strip()
                domain = input("Domaine LDAP (ex: example.com) : ").strip() or "example.com"
                ldap_manager.add_ldap_user(user_cn, domain)
            elif num == 4:
                domain = input("Domaine LDAP (ex: example.com) : ").strip() or "example.com"
                ldap_manager.list_ldap_users(domain)
            elif num == 5:
                confirmation = input("Êtes-vous sûr de vouloir PURGER OpenLDAP ? (yes/no) : ").lower()
                if confirmation == "yes":
                    ldap_manager.remove_ldap_config()
                else:
                    menu_print("[INFO] Suppression annulée.", level="INFO")
            elif num == 6:
                user_cn = input("Nom (cn) de l'utilisateur à supprimer : ").strip()
                domain = input("Domaine LDAP (ex: example.com) : ").strip() or "example.com"
                admin_pass = getpass("Entrez le mot de passe admin LDAP : ").strip() or "admin"
                ldap_manager.delete_ldap_user(user_cn, domain, admin_pass)
            elif num == 7:
                ou_name = input("Nom de l'OU à ajouter : ").strip()
                domain = input("Domaine LDAP (ex: example.com) : ").strip() or "example.com"
                admin_pass = getpass("Entrez le mot de passe admin LDAP : ").strip() or "admin"
                ldap_manager.add_ou(ou_name, domain, admin_pass)
            elif num == 8:
                ou_name = input("Nom de l'OU à supprimer : ").strip()
                domain = input("Domaine LDAP (ex: example.com) : ").strip() or "example.com"
                admin_pass = getpass("Entrez le mot de passe admin LDAP : ").strip() or "admin"
                ldap_manager.remove_ou(ou_name, domain, admin_pass)
            elif num == 9:
                domain = input("Domaine LDAP (ex: example.com) : ").strip() or "example.com"
                ldap_manager.list_ous(domain)
            elif num == 10:
                break
        else:
            if num == 1:
                domain = input("Domaine LDAP (ex: example.com) : ").strip() or "example.com"
                ldap_manager.list_ldap_users(domain)
            elif num == 2:
                break
        input("Appuyez sur Entrée pour continuer...")

def linux_user_menu(user_manager, is_admin):
    while True:
        clear_screen()
        options = []
        # Si l'utilisateur est admin, il peut effectuer des actions sur les utilisateurs Linux
        # Sinon, il peut seulement lister les utilisateurs
        if is_admin:
            options.extend([
                "Créer un utilisateur",
                "Supprimer un utilisateur",
                "Changer un mot de passe",
                "Ajouter un groupe à un utilisateur",
                "Supprimer un groupe pour un utilisateur"
            ])
        # Options communes pour tous
        options.extend([
            "Lister les groupes d'un utilisateur",
            "Lister les utilisateurs",
            "Retour au menu principal"
        ])
        
        choice = display_menu(options)
        if choice is None:
            input("Appuyez sur Entrée pour continuer...")
            continue

        if is_admin:
            if choice == 1:
                username = input("Nom de l'utilisateur : ")
                password = getpass("Mot de passe : ")
                user_manager.create_user(username, password)
            elif choice == 2:
                username = input("Nom de l'utilisateur : ")
                confirm = input(f"Êtes-vous sûr de vouloir supprimer l'utilisateur {username} ? (yes/no) : ").lower()
                if confirm == "yes":
                    user_manager.delete_user(username)
                else:
                    menu_print("[INFO] Suppression annulée.", level="INFO")
            elif choice == 3:
                username = input("Nom de l'utilisateur : ")
                new_password = getpass("Nouveau mot de passe : ")
                user_manager.change_password(username, new_password)
            elif choice == 4:
                username = input("Nom de l'utilisateur : ")
                group_name = input("Nom du groupe à ajouter : ")
                user_manager.add_group_user(username, group_name)
            elif choice == 5:
                username = input("Nom de l'utilisateur : ")
                group_name = input("Nom du groupe à supprimer : ")
                user_manager.del_group_user(username, group_name)
            elif choice == 6:
                username = input("Nom de l'utilisateur (laisser vide pour lister tous les groupes) : ")
                user_manager.list_groups(username)
            elif choice == 7:
                user_manager.list_users()
            elif choice == 8:
                break
        else:
            if choice == 1:
                username = input("Nom de l'utilisateur (laisser vide pour lister tous les groupes) : ")
                user_manager.list_groups(username)
            elif choice == 2:
                user_manager.list_users()
            elif choice == 3:
                break
        input("Appuyez sur Entrée pour continuer...")

def network_menu(network_manager, is_admin):
    while True:
        clear_screen()
        options = []
        # Si l'utilisateur est admin, il peut effectuer des actions sur le réseau
        # Sinon, il peut seulement lister les interfaces réseau
        options.append("Lister les interfaces réseau")
        if is_admin:
            options.extend([
                "Activer une interface",
                "Désactiver une interface",
                "Configurer une IP statique",
                "Configurer une IP dynamique (DHCP)",
                "Lister les baux DHCP",
                "Configurer les serveurs DNS",
                "Reset les DNS",
                "Lister les DNS actuels"
            ])
        options.append("Retour au menu principal")
        num = display_menu(options)
        if num is None:
            input("Appuyez sur Entrée pour continuer...")
            continue
        if num == 1:
            network_manager.list_interfaces_details()
        elif is_admin:
            if num == 2:
                menu_print("[INFO] Interfaces disponibles :", level="INFO")
                network_manager.list_interfaces_details()
                interface = input("Entrez le nom de l'interface à activer : ")
                network_manager.enable_interface(interface)
            elif num == 3:
                menu_print("[INFO] Interfaces disponibles :", level="INFO")
                network_manager.list_interfaces_details()
                interface = input("Entrez le nom de l'interface à désactiver : ")
                network_manager.disable_interface(interface)
            elif num == 4:
                menu_print("[INFO] Interfaces disponibles :", level="INFO")
                network_manager.list_interfaces_details()
                interface = input("Entrez le nom de l'interface à configurer : ")
                ip = input("Entrez l'adresse IP : ")
                netmask = input("Entrez le masque de sous-réseau (ex: 255.255.255.0) : ")
                gateway = input("Entrez la passerelle par défaut : ")
                network_manager.configure_static_ip(interface, ip, netmask, gateway)
            elif num == 5:
                menu_print("[INFO] Interfaces disponibles :", level="INFO")
                network_manager.list_interfaces_details()
                interface = input("Entrez le nom de l'interface à configurer en DHCP : ")
                network_manager.configure_dhcp(interface)
                network_manager.list_dhcp_leases()
            elif num == 6:
                network_manager.list_dhcp_leases()
            elif num == 7:
                primary_dns = input("Entrez l'adresse du DNS primaire : ")
                secondary_dns = input("Entrez l'adresse du DNS secondaire (laisser vide si aucun) : ")
                secondary_dns = secondary_dns if secondary_dns.strip() != "" else None
                network_manager.set_dns(primary_dns, secondary_dns)
            elif num == 8:
                network_manager.reset_dns()
            elif num == 9:
                network_manager.list_dns()
            elif num == 10:
                break
        else:
            if num == 2:
                break
        input("Appuyez sur Entrée pour continuer...")

def main_menu(package_manager, web_manager, ftp_manager, ldap_manager, linux_user_manager, network_manager, is_admin):
    while True:
        clear_screen()
        # Menu principal
        options = [
            "Gestion des paquets classiques",
            "Gestion du serveur Web",
            "Gestion du serveur FTP",
            "Gestion du serveur LDAP",
            "Gestion des utilisateurs Linux",
            "Gestion du réseau et DNS",
            "Quitter"
        ]
        # Affichage du menu principal
        num = display_menu(options)
        if num is None:
            input("Appuyez sur Entrée pour continuer...")
            continue
        if num == 1:
            package_menu(package_manager, is_admin)
        elif num == 2:
            web_menu(web_manager, is_admin)
        elif num == 3:
            ftp_menu(ftp_manager, is_admin)
        elif num == 4:
            ldap_menu(ldap_manager, is_admin)
        elif num == 5:
            linux_user_menu(linux_user_manager, is_admin)
        elif num == 6:
            network_menu(network_manager, is_admin)
        elif num == 7:
            logger.info("[INFO] Fermeture du programme.")
            break
        input("Appuyez sur Entrée pour continuer...")

# Point d'entrée du programme
if __name__ == "__main__":
    clear_screen()
    # Authentification SSH
    hostname = input("Entrez le nom d'hôte ou l'adresse IP de la machine distante : ")
    ssh_user, ssh_pass, is_admin = authenticate_remote(hostname)
    # Vérification des informations d'authentification
    if not ssh_user or not ssh_pass:
        logger.error("[ERREUR] Impossible de continuer sans authentification correcte.")
        exit(1)

    # Connexion SSH
    logger.info(f"[INFO] Connexion SSH établie avec l'utilisateur {ssh_user} sur {hostname}.")

    # Initialisation des managers SSH pour chaque fonctionnalité
    logger.info("[INFO] Initialisation des managers SSH.")
    # Les managers sont initialisés avec les informations d'authentification SSH
    try:
        package_manager = SSHPackageManager(hostname, ssh_user, ssh_pass)
        web_manager = WebManager(hostname, ssh_user, ssh_pass)
        ftp_manager = FTPManager(hostname, ssh_user, ssh_pass)
        ldap_manager = LDAPManager(hostname, ssh_user, ssh_pass)
        linux_user_manager = LinuxUserManager(hostname, ssh_user, ssh_pass)
        network_manager = NetworkManager(hostname, ssh_user, ssh_pass)
    except Exception as e:
        logger.error(f"[ERREUR] Impossible d'initialiser les managers : {str(e)}")
        exit(1)

    # Menu principal
    logger.info("[INFO] Activation des logs.")
    logging.basicConfig(filename="server_manager.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    logger.info("[INFO] Affichage du menu principal.")
    main_menu(package_manager, web_manager, ftp_manager, ldap_manager, linux_user_manager, network_manager, is_admin)

    # Fermeture des connexions SSH
    logger.info("[INFO] Fermeture des connexions SSH.")
    package_manager.close_connection()
    web_manager.close_connection()
    ftp_manager.close_connection()
    ldap_manager.close_connection()
    linux_user_manager.close_connection()
    network_manager.close_connection()
    logger.info("[INFO] Connexions SSH fermées.")
    logger.info("[INFO] Fermeture du programme.")
    logger.info("[INFO] Désactivation des logs.")
    # Fermeture des logs
    logging.shutdown()
    exit(0)

