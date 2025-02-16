import paramiko
from getpass import getpass

# On importe les classes définies dans sshpackagemanager.py
from sshpackagemanager import (
    SSHPackageManager,
    WebManager,
    FTPManager,
    LDAPManager,
    LinuxUserManager
)


def package_menu(package_manager, is_admin):
    """
    Menu dédié à la gestion des paquets classiques (installation, suppression, etc.).
    'is_admin' détermine si l'utilisateur a le droit d'effectuer des tâches avec 'sudo'.
    """
    while True:
        print("\n[ MENU Paquets Classiques ]")
        if is_admin:
            print("1. Installer des paquets")
            print("2. Désinstaller un paquet")
            print("3. Mettre à jour un paquet")
        print("4. Vérifier l'installation d'un paquet")
        print("5. Retour au menu principal")

        choice = input("Sélectionnez une option : ")

        if choice == "1" and is_admin:
            packages = input("Entrez les paquets à installer (séparés par des espaces) : ")
            package_manager.install_packages(packages)
        elif choice == "2" and is_admin:
            package = input("Entrez le nom du paquet à désinstaller : ")
            package_manager.remove_package(package)
        elif choice == "3" and is_admin:
            package = input("Entrez le nom du paquet à mettre à jour : ")
            package_manager.update_package(package)
        elif choice == "4":
            package = input("Entrez le nom du paquet à vérifier : ")
            package_manager.verify_package(package)
        elif choice == "5":
            break
        else:
            print("[ERREUR] Choix invalide ou accès refusé.")


def web_menu(web_manager, is_admin):
    """
    Menu dédié à la gestion Web (Apache) : installation, configuration de site,
    suppression, et affichage de la config.
    """
    while True:
        print("\n[ MENU Web ]")
        if is_admin:
            print("1. Installer Apache2 + PHP")
            print("2. Configurer Apache2 (Nouveau site)")
            print("3. Supprimer un site")
        print("4. Afficher la configuration Web")
        print("5. Retour au menu principal")

        choice = input("Sélectionnez une option : ")

        if choice == "1" and is_admin:
            # Installe apache2, php8.2, etc.
            web_manager.install_packages("apache2 php8.2 libapache2-mod-php8.2")
        elif choice == "2" and is_admin:
            site_name = input("Nom du site : ")
            port = input("Port (par défaut 80) : ")
            if not port.strip():
                port = 80
            web_manager.configure_apache2(site_name, int(port))
        elif choice == "4":
            # Affiche la config d'un site existant
            print("\nSites disponibles :")
            sites = web_manager.list_apache_sites()
            if sites:
                for idx, site in enumerate(sites, 1):
                    print(f"{idx}. {site}")
                site_index = int(input("Sélectionnez le site à afficher (numéro) : ")) - 1
                if 0 <= site_index < len(sites):
                    web_manager.print_web_configuration(sites[site_index])
                else:
                    print("[ERREUR] Choix invalide.")
            else:
                print("[INFO] Aucun site Apache trouvé.")
        elif choice == "3" and is_admin:
            # Supprime un site web
            print("\nSites disponibles :")
            sites = web_manager.list_apache_sites()
            if sites:
                for idx, site in enumerate(sites, 1):
                    print(f"{idx}. {site}")
                site_index = int(input("Sélectionnez le site à supprimer (numéro) : ")) - 1
                if 0 <= site_index < len(sites):
                    confirmation = input(
                        f"Êtes-vous sûr de vouloir supprimer le site '{sites[site_index]}' ? (yes/no) : "
                    ).lower()
                    if confirmation == "yes":
                        web_manager.delete_apache_site(sites[site_index])
                        print(f"[INFO] Site '{sites[site_index]}' supprimé avec succès.")
                    else:
                        print("[INFO] Suppression annulée.")
                else:
                    print("[ERREUR] Choix invalide.")
            else:
                print("[INFO] Aucun site Apache trouvé.")
        elif choice == "5":
            break
        else:
            print("[ERREUR] Choix invalide ou accès refusé.")


def ftp_menu(ftp_manager, is_admin):
    """
    Menu dédié au serveur FTP : installation, configuration (vsftpd),
    affichage de la config.
    """
    while True:
        print("\n[ MENU FTP ]")
        if is_admin:
            print("1. Installer le serveur FTP (vsftpd)")
            print("2. Configurer le serveur FTP")
        print("3. Afficher la configuration FTP")
        print("4. Retour au menu principal")

        choice = input("Sélectionnez une option : ")

        if choice == "1" and is_admin:
            ftp_manager.install_single_package("vsftpd")
        elif choice == "2" and is_admin:
            print("\nConfiguration du serveur FTP (vsftpd) :")
            anonymous_enable = input("Autoriser les connexions anonymes ? (yes/no) : ").strip().lower()
            local_enable = input("Autoriser les utilisateurs locaux ? (yes/no) : ").strip().lower()
            write_enable = input("Autoriser les écritures (upload) ? (yes/no) : ").strip().lower()
            ftp_manager.configure_vsftpd(anonymous_enable, local_enable, write_enable)
        elif choice == "3":
            # Affiche la config ftp
            ftp_manager.print_ftp_configuration()
        elif choice == "4":
            break
        else:
            print("[ERREUR] Choix invalide ou accès refusé.")


def ldap_menu(ldap_manager, is_admin):
    while True:
        print("\n[ MENU LDAP ]")
        if is_admin:
            print("1. Installer & configurer OpenLDAP (non-interactif)")
            print("2. Reconfigurer OpenLDAP (changer domaine, org, mot de passe)")
            print("3. Ajouter un utilisateur LDAP")
            print("4. Lister les utilisateurs LDAP")
            print("5. Supprimer la configuration OpenLDAP")
        print("6. Retour au menu principal")

        choice = input("Sélectionnez une option : ")

        if choice == "1" and is_admin:
            domain = input("Entrez le nom de domaine LDAP (ex: example.com) : ").strip()
            if not domain:
                domain = "example.com"
            org = input("Entrez le nom de l'organisation (ex: ExampleOrg) : ").strip()
            if not org:
                org = "ExampleOrg"
            admin_pass = input("Entrez le mot de passe admin LDAP : ").strip()
            if not admin_pass:
                admin_pass = "admin"

            ldap_manager.install_and_configure_ldap_via_script(domain, org, admin_pass)

        elif choice == "2" and is_admin:
            domain = input("Entrez le nouveau domaine LDAP (ex: example.com) : ").strip()
            if not domain:
                domain = "example.com"
            org = input("Entrez le nouveau nom de l'organisation (ex: ExampleOrg) : ").strip()
            if not org:
                org = "ExampleOrg"
            admin_pass = input("Entrez le nouveau mot de passe admin LDAP : ").strip()
            if not admin_pass:
                admin_pass = "admin"

            ldap_manager.configure_ldap(domain=domain, org_name=org, admin_password=admin_pass)

        elif choice == "3" and is_admin:
            user_cn = input("Nom (cn) de l'utilisateur à ajouter : ").strip()
            domain = input("Domaine LDAP (ex: example.com) : ").strip()
            if not domain:
                domain = "example.com"
            ldap_manager.add_ldap_user(user_cn, domain)

        elif choice == "4" and is_admin:
            domain = input("Domaine LDAP (ex: example.com) : ").strip()
            if not domain:
                domain = "example.com"
            ldap_manager.list_ldap_users(domain)

        elif choice == "5" and is_admin:
            confirmation = input("Êtes-vous sûr de vouloir PURGER OpenLDAP ? (yes/no) : ").lower()
            if confirmation == "yes":
                ldap_manager.remove_ldap_config()
            else:
                print("[INFO] Suppression annulée.")

        elif choice == "6":
            break
        else:
            print("[ERREUR] Choix invalide ou accès refusé.")


def linux_user_menu(user_manager, is_admin):
    """
    Menu de gestion des utilisateurs Linux : création, suppression,
    changement de mot de passe, listing des groupes.
    """
    while True:
        print("\n[ MENU Utilisateurs Linux ]")
        if is_admin:
            print("1. Créer un utilisateur")
            print("2. Supprimer un utilisateur")
            print("3. Changer un mot de passe")
        print("4. Lister les groupes (d'un utilisateur)")
        print("5 Lister les utilisateurs")
        print("6. Retour au menu principal")

        choice = input("Sélectionnez une option : ")

        if choice == "1" and is_admin:
            username = input("Nom de l'utilisateur : ")
            password = input("Mot de passe : ")
            user_manager.create_user(username, password)
        elif choice == "2" and is_admin:
            username = input("Nom de l'utilisateur : ")
            confirmation = input(f"Êtes-vous sûr de vouloir supprimer l'utilisateur {username} ? (yes/no) : ").lower()
            if confirmation == "yes":
                user_manager.delete_user(username)
            else:
                print("[INFO] Suppression annulée.")
        elif choice == "3" and is_admin:
            username = input("Nom de l'utilisateur : ")
            new_password = input("Nouveau mot de passe : ")
            user_manager.change_password(username, new_password)
        elif choice == "4":
            username = input("Nom de l'utilisateur (laisser vide pour lister tous les groupes) : ")
            user_manager.list_groups(username)
        elif choice == "5":
            user_manager.list_users()
        elif choice == "6":
            break
        else:
            print("[ERREUR] Choix invalide ou accès refusé.")


def main_menu(package_manager, web_manager, ftp_manager, ldap_manager, linux_user_manager, is_admin):
    """
    Menu principal qui redirige vers les sous-menus
    (paquets, web, ftp, ldap, users).
    """
    while True:
        print("\n[ MENU PRINCIPAL ]")
        print("1. Gestion des paquets classiques")
        print("2. Gestion des paquets web (Apache)")
        print("3. Gestion du serveur FTP")
        print("4. Gestion du serveur LDAP")
        print("5. Gestion des utilisateurs Linux")
        print("6. Quitter")

        choice = input("Sélectionnez une option : ")

        if choice == "1":
            package_menu(package_manager, is_admin)
        elif choice == "2":
            web_menu(web_manager, is_admin)
        elif choice == "3":
            ftp_menu(ftp_manager, is_admin)
        elif choice == "4":
            ldap_menu(ldap_manager, is_admin)
        elif choice == "5":
            linux_user_menu(linux_user_manager, is_admin)
        elif choice == "6":
            print("[INFO] Fermeture du programme.")
            break
        else:
            print("[ERREUR] Choix invalide.")


def authenticate_remote(hostname):
    """
    Fonction qui demande un login/password SSH,
    tente une connexion Paramiko,
    puis vérifie si l'utilisateur est dans un groupe admin/sudo.
    """
    print("[AUTH] Authentification requise...")
    user = input("Nom d'utilisateur SSH : ")
    password = input("Mot de passe SSH : ")

    temp_client = paramiko.SSHClient()
    temp_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        temp_client.connect(hostname, username=user, password=password)
    except Exception as e:
        print(f"[ERREUR] Échec de la connexion SSH : {str(e)}")
        return None, None, False

    # Récupère la liste des groupes de l'utilisateur
    stdin, stdout, stderr = temp_client.exec_command(f"id -nG {user}")
    groups = stdout.read().decode().strip().split()
    temp_client.close()

    # Détermine si l'utilisateur est admin en fonction de ses groupes (ex: 'sudo' ou 'admin')
    is_admin = ('sudo' in groups) or ('admin' in groups)
    return user, password, is_admin


if __name__ == "__main__":
    # Hostname / IP de la machine distante
    hostname = "192.168.8.131"

    # On effectue l'authentification SSH
    ssh_user, ssh_pass, is_admin = authenticate_remote(hostname)
    if not ssh_user or not ssh_pass:
        print("[ERREUR] Impossible de continuer sans authentification correcte.")
        exit(1)

    # Création des objets managers
    package_manager = SSHPackageManager(hostname, ssh_user, ssh_pass)
    web_manager = WebManager(hostname, ssh_user, ssh_pass)
    ftp_manager = FTPManager(hostname, ssh_user, ssh_pass)
    ldap_manager = LDAPManager(hostname, ssh_user, ssh_pass)
    linux_user_manager = LinuxUserManager(hostname, ssh_user, ssh_pass)

    try:
        # Lance le menu principal
        main_menu(
            package_manager,
            web_manager,
            ftp_manager,
            ldap_manager,
            linux_user_manager,
            is_admin
        )
    finally:
        # On ferme toutes les connexions SSH proprement à la fin
        package_manager.close_connection()
        web_manager.close_connection()
        ftp_manager.close_connection()
        ldap_manager.close_connection()
        linux_user_manager.close_connection()
        print("[INFO] Connexions SSH fermées.")
