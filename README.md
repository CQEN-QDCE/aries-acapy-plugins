# aries-acapy-plugins

Ce dépôt contient des extensions approuvés et testés pour le Aries Cloudagent Python (ACA-Py). La pssibilité d'étendre ACA-Py a pour but d'encourager la collaboration et le partage de fonctionnalités utiles qui ne sont pas directement incluse. Deux(2) extensions supplémentaire ont été ajouté. Une pour créer un mDL et l'autre pour permettre l'émission d'attestations vérifiables (dont le mDL) via le protocole OID4VCI.

## Notes aux développeurs

- Ouvrir le "devcontainer" dans VS Code
- Python et toutes les d/pendences vont être chargées
- Poetry va être chargé et paramétré, les dépendences vont être installées
- Docker et Docker Compose vont être disponibles

## Documentation de l'extension

L'équipe de développement devrait décrire ce que fait l'extension, toutes les limitations éventuelles, tous les problèmes connus d'interaction avec d'autres plugins, etc. Une documentation complète, incluant un exemple de plugin_config, devrait être fournie.

Cette documentation devrait être fournie à la racine de votre extension sous forme de fichier README.md. Avec au moins une section "Description" et une section "Configuration".

## Construire et exécuter

Un fichier [Dockerfile](./basicmessage_storage/docker/Dockerfile) est founi pour exécuter les tests d'intégration. Cette image n'est pas destinée à la production car elle copie le code source de l'extension et charge ses dépendances (y compris ACA-Py) ainsi qu'un fichier de configuration ACA-Py simplifié.: [default.yml](./basicmessage_storage/docker/default.yml).

## Exécuter et déboguer

Dans le devcontainer, vous pouvez exécuter une instance ACA-Py avec vos sources d'extension chargées et définir des points d'arrêt pour déboguer (voir `launch.json`).

Pour exécuter votre code ACA-Py en mode débogue, accédez à la vue "exécuter et déboguer", sélectionnez "Run/Debug Plugin" et appuyez sur "Démarrer le déboguage (F5)". Utilisant [default.yml](./basicmessage_storage/docker/default.yml), votre agent swagger est disponible à l'adresse http://localhost:3001/api/doc.

## Test

Pour que l'extension soit acceptée dans ce dépôt, elle doit avoir été soumise à des tests adéquats.

#### Tests unitaires:
- Il devrait y avoir une couverture adéquate de tests unitaires. Un rapport de couverture est généré lorsque la commande poetry run pytest . est exécutée depuis le devcontainer. Un bon objectif à viser est 90%, mais la qualité des tests sur les sections critiques est plus importante que le pourcentage de couverture.
coverage percentage.
- Placez vos tests unitaires dans un dossier 'tests' dans le chemin de version de votre extension et nommez tous les fichiers et tests avec le préfixe test_.

#### Tests d'integration:
- Tous les extensions devraient avoir une suite de tests d'intégration. La suite de base sera créée pour votre extension après l'exécution du script de mise à jour.
- Voir [integration tests](./basicmessage_storage/integration/README.md). Vous devriez avoir tout ce dont vous avez besoin pour commencer les tests d'intégration, et un test d'exemple sera fourni.

## Déploiement

Pour une utilisation en production, les extensions doivent être installêes comme des bibliothèques dans une image ACA-Py.

Cela requiert d'avoir un fichier Docker et un fichier de paramètres pour votre agent.

exemple de fichier Docker:

```
FROM ghcr.io/hyperledger/aries-cloudagent-python:py3.9-0.11.0

USER root

# install plugins as binaries
RUN pip install git+https://github.com/hyperledger/aries-acapy-plugins@main#subdirectory=basicmessage_storage
RUN pip install git+https://github.com/hyperledger/aries-acapy-plugins@main#subdirectory=connection_update

USER $user
COPY ./configs configs

CMD ["aca-py"]
```

exemple de fichier de paramétrage:

```
label: plugins-agent

admin-insecure-mode: true
admin: [0.0.0.0, 9061]

inbound-transport:
   - [http, 0.0.0.0, 9060]
outbound-transport: http
endpoint: http://host.docker.internal:9060

genesis-url: http://test.bcovrin.vonx.io/genesis

emit-new-didcomm-prefix: true
wallet-type: askar
wallet-storage-type: default

auto-provision: true
debug-connections: true
auto-accept-invites: true
auto-accept-requests: true
auto-ping-connection: true
auto-respond-messages: true

log-level: info

plugin:
  - basicmessage_storage.v1_0
  - connection_update.v1_0
```

Maintenant, vous pouvez déployer un agent avec autant de d'extensions que vous le souhaitez, à condition qu'ils soient déclarés dans votre fichier de configuration de build et installés.

```
docker build -f <Dockerfile> --tag acapy_plugins .
docker run -it -p 9060:9060 -p 9061:9061 --rm acapy_plugins start --arg-file=<config-file> -->
```
