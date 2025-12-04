Voici une phase de reconnaissance utilisant **uniquement PowerShell** (principalement le module Microsoft Active Directory et des commandes natives), sans utiliser PowerView, basée sur les sources fournies.

### 1. Chargement des Modules
Si les outils RSAT ne sont pas installés mais que vous avez accès à la DLL, vous pouvez importer le module manuellement,.

```powershell
# Importer le module Active Directory depuis une DLL (si disponible localement)
Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll
Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1
```

### 2. Informations sur le Domaine et Politiques
Récupération des informations de base sur le domaine courant et les politiques de mots de passe,.

```powershell
# Obtenir les informations du domaine courant
Get-ADDomain

# Obtenir le contrôleur de domaine racine (RootDSE)
Get-ADRootDSE

# Récupérer la politique de mot de passe par défaut du domaine (Default Domain Policy)
Get-ADDefaultDomainPasswordPolicy

# Récupérer les politiques de mot de passe affinées (FGPP / Password Settings Objects)
# Nécessite souvent des privilèges, mais peut être tenté.
Get-ADFineGrainedPasswordPolicy -Filter *
```

### 3. Énumération des Utilisateurs et Groupes
Identification des utilisateurs, des administrateurs et des groupes sensibles,.

```powershell
# Lister tous les utilisateurs avec des propriétés détaillées
Get-ADUser -Filter * -Properties *

# Rechercher un utilisateur spécifique (ex: contenant "admin" dans le nom)
Get-ADUser -Filter 'SamAccountName -like "*admin*"' -Properties Description, LastLogonDate

# Obtenir les membres du groupe "Domain Admins"
Get-ADGroupMember -Identity "Domain Admins" -Recursive

# Obtenir les groupes dont un utilisateur spécifique est membre
Get-ADPrincipalGroupMembership -Identity "nom_utilisateur"

# Rechercher des comptes spécifiques liés à Azure AD Connect (MSOL_*) pour cibler le PHS
Get-ADUser -Filter "samAccountName -like 'MSOL_*'" -Properties * | select SamAccountName, Description
```

### 4. Attaques Kerberoasting (SPN)
Identification des comptes de service vulnérables au Kerberoasting (comptes utilisateurs avec un Service Principal Name),.

```powershell
# Lister tous les utilisateurs possédant un SPN (Service Principal Name) non nul
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

### 5. Énumération des Ordinateurs et Contrôleurs de Domaine
Inventaire des machines et identification des systèmes d'exploitation.

```powershell
# Lister tous les ordinateurs du domaine avec leur système d'exploitation
Get-ADComputer -Filter * -Properties OperatingSystem, OperatingSystemVersion

# Trouver des contrôleurs de domaine spécifiques
Get-ADDomainController -Filter *
```

### 6. Relations d'Approbation (Trusts) et Forêts
Cartographie des relations de confiance entre domaines et forêts pour les mouvements latéraux,.

```powershell
# Lister les relations d'approbation (Trusts) du domaine courant
Get-ADTrust -Filter *

# Identifier spécifiquement les trusts inter-forêts (Forest Transitive)
Get-ADTrust -Filter 'IntraForest -ne $true'

# Énumérer les domaines de la forêt courante
(Get-ADForest).Domains
```

### 7. Objets Spéciaux et Configuration Avancée
Recherche de principaux de sécurité étrangers (Foreign Security Principals) et d'objets liés aux trusts PAM ou Shadow Principals,.

```powershell
# Rechercher des Foreign Security Principals (indique souvent des groupes inter-domaines/forêts)
Get-ADObject -Filter {objectClass -eq "foreignSecurityPrincipal"}

# Rechercher des Shadow Principals (utilisés dans les trusts PAM/Red Forest)
Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Filter * -Properties *
```

### 8. Commandes Natives / WMI (Sans module AD)
Si le module AD n'est pas disponible, ces commandes natives peuvent aider.

```powershell
# Informations sur le système d'exploitation via WMI
Get-WmiObject -Class win32_operatingsystem

# Lister les processus locaux
Get-Process

# Lister les connexions réseau actives
Get-NetTCPConnection
```