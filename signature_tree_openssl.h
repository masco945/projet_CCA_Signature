#ifndef SIGNATURE_TREE_OPENSSL_H
#define SIGNATURE_TREE_OPENSSL_H

/*
 * ============================================================
 * Fichier : signature_tree_openssl.h
 * ============================================================
 *
 * Rôle :
 *   Ce fichier est l'en-tête public du module d'arbre de signature.
 *
 *   Il expose :
 *   - les constantes utiles,
 *   - les structures de données publiques,
 *   - les prototypes des fonctions disponibles.
 *
 * Idée générale :
 *   On construit un arbre t-aire de signatures :
 *   - chaque nœud contient une paire de clés Ed25519,
 *   - chaque nœud interne possède t fils,
 *   - la clé publique d’un fils est signée par le parent,
 *   - chaque nœud terminal contient t messages à signer.
 *
 *   Le module permet ensuite :
 *   - de construire l’arbre,
 *   - de signer le prochain message disponible,
 *   - de vérifier le chemin d’authentification complet,
 *   - d’afficher et libérer l’arbre.
 */

#include <stddef.h>
#include <openssl/evp.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Taille d'une clé publique Ed25519 brute.
 * Ed25519 encode la clé publique sur 32 octets.
 */
#define ST_ED25519_PUBKEY_LEN 32

/*
 * Taille d'une signature Ed25519 brute.
 * Une signature Ed25519 mesure 64 octets.
 */
#define ST_ED25519_SIG_LEN    64

/*
 * Taille maximale d'un message stocké dans une feuille.
 * Les messages sont stockés ici sous forme de chaîne C.
 */
#define ST_MAX_MSG_LEN        256

/*
 * ============================================================
 * Structure : ST_Buffer
 * ============================================================
 *
 * Rôle :
 *   Représenter un bloc d’octets de taille variable.
 *
 * Utilisation :
 *   Sert à stocker :
 *   - une signature,
 *   - tout autre tableau dynamique d’octets si besoin.
 *
 * Champs :
 *   data : pointeur vers les octets
 *   len  : longueur en octets
 */
typedef struct {
    unsigned char *data;
    size_t len;
} ST_Buffer;

/*
 * ============================================================
 * Structure : ST_MessageLeaf
 * ============================================================
 *
 * Rôle :
 *   Représenter une feuille terminale de l’arbre.
 *
 * Idée :
 *   Chaque feuille correspond à un message signable une seule fois.
 *
 * Champs :
 *   message : contenu du message
 *   sig     : signature du message par la clé du nœud terminal
 *   used    : indique si le message a déjà été signé
 *             0 = pas encore signé
 *             1 = déjà signé
 */
typedef struct {
    char message[ST_MAX_MSG_LEN];
    ST_Buffer sig;
    int used;
} ST_MessageLeaf;

/*
 * ============================================================
 * Structure : ST_SignatureNode
 * ============================================================
 *
 * Rôle :
 *   Représenter un nœud de l’arbre de signature.
 *
 * Chaque nœud contient :
 *   - une paire de clés Ed25519,
 *   - sa clé publique brute,
 *   - éventuellement la signature de sa clé publique par son parent,
 *   - ses fils,
 *   - éventuellement ses feuilles terminales.
 *
 * Champs :
 *   pkey            : clé OpenSSL contenant à la fois la clé privée
 *                     et la clé publique du nœud
 *
 *   pubkey          : clé publique brute du nœud (32 octets)
 *   pubkey_len      : longueur de la clé publique brute
 *
 *   auth_from_parent:
 *       signature de pubkey par la clé privée du parent
 *
 *   has_parent_auth :
 *       vaut 0 pour la racine,
 *       vaut 1 pour tout autre nœud
 *
 *   children        : tableau dynamique de pointeurs vers les fils
 *   nb_children     : nombre de fils
 *
 *   leaves          : tableau des feuilles terminales
 *   nb_leaves       : nombre de feuilles terminales
 *
 * Remarque :
 *   Un nœud interne possède des children.
 *   Un nœud terminal possède des leaves.
 */
typedef struct ST_SignatureNode {
    EVP_PKEY *pkey;

    unsigned char pubkey[ST_ED25519_PUBKEY_LEN];
    size_t pubkey_len;

    ST_Buffer auth_from_parent;
    int has_parent_auth;

    struct ST_SignatureNode **children;
    size_t nb_children;

    ST_MessageLeaf *leaves;
    size_t nb_leaves;
} ST_SignatureNode;

/*
 * ============================================================
 * Structure : ST_SignResult
 * ============================================================
 *
 * Rôle :
 *   Représenter le résultat complet d’une signature.
 *
 * Cette structure contient :
 *   - le message signé,
 *   - sa signature,
 *   - le chemin de nœuds depuis la racine jusqu’au nœud terminal,
 *   - les indices de fils utilisés pour suivre ce chemin,
 *   - l’indice de la feuille signée.
 *
 * Champs :
 *   success :
 *       1 si la signature a réussi,
 *       0 s’il n’y avait plus aucun message disponible
 *
 *   message :
 *       message effectivement signé
 *
 *   message_signature :
 *       signature du message par le nœud terminal
 *
 *   path_nodes :
 *       tableau des nœuds du chemin racine -> nœud terminal
 *
 *   path_child_indexes :
 *       pour chaque niveau interne, indique quel fils a été choisi
 *       pour descendre au nœud suivant
 *
 *   path_len :
 *       longueur du chemin (nombre de nœuds dans path_nodes)
 *
 *   leaf_index :
 *       indice de la feuille-message choisie dans le nœud terminal
 */
typedef struct {
    int success;

    char message[ST_MAX_MSG_LEN];
    ST_Buffer message_signature;

    ST_SignatureNode **path_nodes;
    size_t *path_child_indexes;
    size_t path_len;

    size_t leaf_index;
} ST_SignResult;

/* ============================================================
 * INITIALISATION / NETTOYAGE OPENSSL
 * ============================================================
 */

/*
 * Fonction : st_openssl_init
 * --------------------------------
 * Rôle :
 *   Initialiser OpenSSL pour l'utilisation du module.
 *
 * Utilisation :
 *   À appeler une fois au début du programme, avant toute opération
 *   cryptographique.
 *
 * Retour :
 *   Aucun.
 */
void st_openssl_init(void);

/*
 * Fonction : st_openssl_cleanup
 * --------------------------------
 * Rôle :
 *   Nettoyer les ressources globales OpenSSL.
 *
 * Utilisation :
 *   À appeler en fin de programme après utilisation du module.
 *
 * Retour :
 *   Aucun.
 */
void st_openssl_cleanup(void);

/* ============================================================
 * GESTION DES BUFFERS
 * ============================================================
 */

/*
 * Fonction : st_buffer_init
 * --------------------------------
 * Rôle :
 *   Initialiser un buffer vide.
 *
 * Paramètre :
 *   b : buffer à initialiser
 *
 * Effet :
 *   Met data à NULL et len à 0.
 *
 * Retour :
 *   Aucun.
 */
void st_buffer_init(ST_Buffer *b);

/*
 * Fonction : st_buffer_free
 * --------------------------------
 * Rôle :
 *   Libérer la mémoire allouée par un buffer.
 *
 * Paramètre :
 *   b : buffer à libérer
 *
 * Effet :
 *   Libère data puis remet le buffer à l’état vide.
 *
 * Retour :
 *   Aucun.
 */
void st_buffer_free(ST_Buffer *b);

/* ============================================================
 * CONSTRUCTION DE L’ARBRE
 * ============================================================
 */

/*
 * Fonction : st_create_node
 * --------------------------------
 * Rôle :
 *   Créer un nouveau nœud avec une nouvelle paire de clés Ed25519.
 *
 * Retour :
 *   Un pointeur vers le nœud nouvellement créé.
 *
 * Remarque :
 *   Le nœud créé ne possède encore ni fils ni feuilles terminales.
 */
ST_SignatureNode *st_create_node(void);

/*
 * Fonction : st_add_child
 * --------------------------------
 * Rôle :
 *   Ajouter un fils à un nœud parent.
 *
 * Effet :
 *   - crée un nouveau nœud fils,
 *   - signe sa clé publique avec la clé privée du parent,
 *   - ajoute ce fils dans le tableau children du parent.
 *
 * Paramètre :
 *   parent : nœud auquel on ajoute un fils
 *
 * Retour :
 *   Pointeur vers le fils créé.
 */
ST_SignatureNode *st_add_child(ST_SignatureNode *parent);

/*
 * Fonction : st_add_message_leaves
 * --------------------------------
 * Rôle :
 *   Ajouter t feuilles terminales à un nœud.
 *
 * Paramètres :
 *   node     : nœud terminal auquel ajouter les feuilles
 *   t        : nombre de feuilles à ajouter
 *   messages : tableau de t chaînes de caractères
 *
 * Effet :
 *   Chaque feuille reçoit un message, une signature vide,
 *   et l’état "non utilisé".
 *
 * Retour :
 *   Aucun.
 */
void st_add_message_leaves(ST_SignatureNode *node, size_t t, const char *messages[]);

/*
 * Fonction : st_build_tree
 * --------------------------------
 * Rôle :
 *   Construire récursivement un arbre de signature t-aire.
 *
 * Paramètres :
 *   node     : racine du sous-arbre courant
 *   depth    : profondeur restante
 *   t        : facteur de branchement
 *   messages : messages à placer dans chaque nœud terminal
 *
 * Convention :
 *   - si depth == 1, node devient un nœud terminal et reçoit t feuilles
 *   - sinon, node reçoit t fils, puis on construit récursivement
 *     le sous-arbre de chacun
 *
 * Retour :
 *   Aucun.
 */
void st_build_tree(ST_SignatureNode *node, size_t depth, size_t t, const char *messages[]);

/* ============================================================
 * AFFICHAGE / STATISTIQUES
 * ============================================================
 */

/*
 * Fonction : st_print_tree
 * --------------------------------
 * Rôle :
 *   Afficher récursivement l’arbre à partir d’un nœud.
 *
 * Paramètres :
 *   node  : nœud à afficher
 *   level : niveau d'indentation (souvent 0 à l’appel initial)
 *
 * Retour :
 *   Aucun.
 */
void st_print_tree(const ST_SignatureNode *node, size_t level);

/*
 * Fonction : st_count_total_nodes
 * --------------------------------
 * Rôle :
 *   Compter le nombre total de nœuds dans l’arbre.
 *
 * Paramètre :
 *   node : racine du sous-arbre
 *
 * Retour :
 *   Nombre total de nœuds.
 */
size_t st_count_total_nodes(const ST_SignatureNode *node);

/*
 * Fonction : st_count_total_leaves
 * --------------------------------
 * Rôle :
 *   Compter le nombre total de feuilles-message dans l’arbre.
 *
 * Paramètre :
 *   node : racine du sous-arbre
 *
 * Retour :
 *   Nombre total de feuilles.
 */
size_t st_count_total_leaves(const ST_SignatureNode *node);

/*
 * Fonction : st_count_signed_leaves
 * --------------------------------
 * Rôle :
 *   Compter combien de feuilles-message ont déjà été signées.
 *
 * Paramètre :
 *   node : racine du sous-arbre
 *
 * Retour :
 *   Nombre de feuilles déjà utilisées.
 */
size_t st_count_signed_leaves(const ST_SignatureNode *node);

/* ============================================================
 * SIGNATURE / VERIFICATION
 * ============================================================
 */

/*
 * Fonction : st_sign_next_message
 * --------------------------------
 * Rôle :
 *   Signer automatiquement le prochain message disponible dans l’arbre.
 *
 * Paramètres :
 *   root      : racine de l’arbre
 *   max_depth : profondeur maximale du chemin racine -> feuille terminale
 *
 * Retour :
 *   Une structure ST_SignResult contenant :
 *   - success = 1 si une signature a été produite,
 *   - success = 0 s’il n’y a plus de message libre.
 *
 * Remarque :
 *   L’algorithme parcourt l’arbre de gauche à droite et prend la première
 *   feuille libre rencontrée.
 */
ST_SignResult st_sign_next_message(ST_SignatureNode *root, size_t max_depth);

/*
 * Fonction : st_free_sign_result
 * --------------------------------
 * Rôle :
 *   Libérer les ressources dynamiques d’un résultat de signature.
 *
 * Paramètre :
 *   res : résultat à libérer
 *
 * Retour :
 *   Aucun.
 */
void st_free_sign_result(ST_SignResult *res);

/*
 * Fonction : st_verify_sign_result
 * --------------------------------
 * Rôle :
 *   Vérifier un résultat de signature complet.
 *
 * Effet :
 *   Vérifie :
 *   1) chaque signature de clé publique enfant par le parent,
 *   2) la signature finale du message.
 *
 * Paramètre :
 *   res : résultat de signature à vérifier
 *
 * Retour :
 *   1 si tout est valide,
 *   0 sinon.
 */
int st_verify_sign_result(const ST_SignResult *res);

/* ============================================================
 * LIBERATION MEMOIRE
 * ============================================================
 */

/*
 * Fonction : st_free_tree
 * --------------------------------
 * Rôle :
 *   Libérer récursivement tout l’arbre de signature.
 *
 * Paramètre :
 *   node : racine du sous-arbre à libérer
 *
 * Effet :
 *   Libère :
 *   - les sous-arbres fils,
 *   - les signatures des feuilles,
 *   - les buffers,
 *   - les clés OpenSSL,
 *   - le nœud lui-même.
 *
 * Retour :
 *   Aucun.
 */
void st_free_tree(ST_SignatureNode *node);

#ifdef __cplusplus
}
#endif

#endif