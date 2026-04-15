#include "signature_tree_openssl.h"

/*
 * ============================================================
 * Fichier : signature_tree_openssl.c
 * ============================================================
 *
 * Rôle :
 *   Ce fichier contient l’implémentation complète du module
 *   d’arbre de signature basé sur OpenSSL et Ed25519.
 *
 * Contenu :
 *   - fonctions internes utilitaires,
 *   - génération de clés,
 *   - signature / vérification,
 *   - construction de l’arbre,
 *   - affichage,
 *   - comptage,
 *   - signature du prochain message,
 *   - libération mémoire.
 *
 * Important :
 *   Certaines fonctions sont "static" :
 *   elles sont internes au fichier et ne font pas partie
 *   de l’API publique.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>

/* ============================================================
 * OUTILS INTERNES
 * ============================================================
 */

/*
 * Fonction interne : st_openssl_die
 * --------------------------------
 * Rôle :
 *   Afficher un message d’erreur puis les erreurs OpenSSL,
 *   puis arrêter le programme.
 *
 * Paramètre :
 *   msg : message explicatif
 *
 * Retour :
 *   Aucun. La fonction termine le programme.
 */
static void st_openssl_die(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

/*
 * Fonction interne : st_xmalloc
 * --------------------------------
 * Rôle :
 *   Version sécurisée de malloc.
 *
 * Paramètre :
 *   n : nombre d’octets à allouer
 *
 * Retour :
 *   Pointeur vers la zone allouée.
 *
 * Effet :
 *   Arrête le programme si l’allocation échoue.
 */
static void *st_xmalloc(size_t n) {
    void *p = malloc(n);
    if (!p) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    return p;
}

/*
 * Fonction interne : st_xcalloc
 * --------------------------------
 * Rôle :
 *   Version sécurisée de calloc.
 *
 * Paramètres :
 *   count : nombre d’éléments
 *   size  : taille d’un élément
 *
 * Retour :
 *   Pointeur vers la zone allouée.
 *
 * Effet :
 *   Arrête le programme si l’allocation échoue.
 */
static void *st_xcalloc(size_t count, size_t size) {
    void *p = calloc(count, size);
    if (!p) {
        perror("calloc");
        exit(EXIT_FAILURE);
    }
    return p;
}

/*
 * Fonction interne : st_xrealloc
 * --------------------------------
 * Rôle :
 *   Version sécurisée de realloc.
 *
 * Paramètres :
 *   ptr : ancienne zone mémoire
 *   n   : nouvelle taille en octets
 *
 * Retour :
 *   Nouveau pointeur réalloué.
 *
 * Effet :
 *   Arrête le programme si la réallocation échoue.
 */
static void *st_xrealloc(void *ptr, size_t n) {
    void *p = realloc(ptr, n);
    if (!p) {
        perror("realloc");
        exit(EXIT_FAILURE);
    }
    return p;
}

/*
 * Fonction interne : st_print_indent
 * --------------------------------
 * Rôle :
 *   Afficher une indentation de 2 espaces par niveau.
 *
 * Paramètre :
 *   level : niveau d’indentation
 *
 * Retour :
 *   Aucun.
 */
static void st_print_indent(size_t level) {
    for (size_t i = 0; i < level; i++) {
        printf("  ");
    }
}

/*
 * Fonction interne : st_print_hex_prefix
 * --------------------------------
 * Rôle :
 *   Afficher les premiers octets d’un buffer en hexadécimal.
 *
 * Paramètres :
 *   buf        : tableau d’octets
 *   len        : longueur totale
 *   prefix_len : nombre maximal d’octets à afficher
 *
 * Retour :
 *   Aucun.
 *
 * Utilité :
 *   Permet d’afficher proprement un aperçu des clés/signatures
 *   sans imprimer tout le buffer.
 */
static void st_print_hex_prefix(const unsigned char *buf, size_t len, size_t prefix_len) {
    size_t n = (len < prefix_len) ? len : prefix_len;
    for (size_t i = 0; i < n; i++) {
        printf("%02x", buf[i]);
    }
    if (len > prefix_len) {
        printf("...");
    }
}

/* ============================================================
 * INITIALISATION OPENSSL
 * ============================================================
 */

/*
 * Fonction : st_openssl_init
 * --------------------------------
 * Rôle :
 *   Initialiser les composants OpenSSL utilisés par le module.
 *
 * Retour :
 *   Aucun.
 *
 * Remarque :
 *   Sur certaines versions modernes d’OpenSSL, une partie de cette
 *   initialisation est moins nécessaire qu’avant, mais cela reste
 *   acceptable pour un code pédagogique et explicite.
 */
void st_openssl_init(void) {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
}

/*
 * Fonction : st_openssl_cleanup
 * --------------------------------
 * Rôle :
 *   Libérer les ressources globales OpenSSL initialisées.
 *
 * Retour :
 *   Aucun.
 */
void st_openssl_cleanup(void) {
    EVP_cleanup();
    ERR_free_strings();
}

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
 * Retour :
 *   Aucun.
 */
void st_buffer_init(ST_Buffer *b) {
    if (!b) return;
    b->data = NULL;
    b->len = 0;
}

/*
 * Fonction : st_buffer_free
 * --------------------------------
 * Rôle :
 *   Libérer un buffer dynamique.
 *
 * Paramètre :
 *   b : buffer à libérer
 *
 * Retour :
 *   Aucun.
 */
void st_buffer_free(ST_Buffer *b) {
    if (!b) return;
    free(b->data);
    b->data = NULL;
    b->len = 0;
}

/* ============================================================
 * OUTILS ED25519 INTERNES
 * ============================================================
 */

/*
 * Fonction interne : st_generate_ed25519_key
 * --------------------------------
 * Rôle :
 *   Générer une nouvelle paire de clés Ed25519.
 *
 * Retour :
 *   Un EVP_PKEY* contenant la clé privée et la clé publique.
 *
 * Remarque :
 *   La gestion bas niveau de la clé est entièrement confiée à OpenSSL.
 */
static EVP_PKEY *st_generate_ed25519_key(void) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    EVP_PKEY *pkey = NULL;

    if (!pctx) {
        st_openssl_die("EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519) a echoue");
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        st_openssl_die("EVP_PKEY_keygen_init a echoue");
    }

    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        st_openssl_die("EVP_PKEY_keygen a echoue");
    }

    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

/*
 * Fonction interne : st_extract_raw_public_key
 * --------------------------------
 * Rôle :
 *   Extraire la clé publique brute d’un EVP_PKEY Ed25519.
 *
 * Paramètres :
 *   pkey    : clé OpenSSL source
 *   out     : tableau de sortie de 32 octets
 *   out_len : longueur réellement extraite
 *
 * Retour :
 *   Aucun.
 *
 * Effet :
 *   Copie la clé publique brute dans out.
 */
static void st_extract_raw_public_key(EVP_PKEY *pkey,
                                      unsigned char out[ST_ED25519_PUBKEY_LEN],
                                      size_t *out_len) {
    size_t len = ST_ED25519_PUBKEY_LEN;

    if (EVP_PKEY_get_raw_public_key(pkey, out, &len) <= 0) {
        st_openssl_die("EVP_PKEY_get_raw_public_key a echoue");
    }

    if (len != ST_ED25519_PUBKEY_LEN) {
        fprintf(stderr, "Longueur de cle publique inattendue: %zu\n", len);
        exit(EXIT_FAILURE);
    }

    *out_len = len;
}

/*
 * Fonction interne : st_ed25519_sign
 * --------------------------------
 * Rôle :
 *   Signer un bloc d’octets avec une clé Ed25519.
 *
 * Paramètres :
 *   pkey     : clé contenant la partie privée
 *   data     : données à signer
 *   data_len : taille des données
 *
 * Retour :
 *   Un ST_Buffer contenant la signature brute.
 *
 * Important :
 *   Avec Ed25519, OpenSSL utilise une signature "one-shot"
 *   via EVP_DigestSignInit / EVP_DigestSign.
 */
static ST_Buffer st_ed25519_sign(EVP_PKEY *pkey, const unsigned char *data, size_t data_len) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    size_t sig_len = 0;
    unsigned char *sig = NULL;
    ST_Buffer out;

    st_buffer_init(&out);

    if (!mdctx) {
        st_openssl_die("EVP_MD_CTX_new a echoue");
    }

    if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey) <= 0) {
        EVP_MD_CTX_free(mdctx);
        st_openssl_die("EVP_DigestSignInit a echoue");
    }

    if (EVP_DigestSign(mdctx, NULL, &sig_len, data, data_len) <= 0) {
        EVP_MD_CTX_free(mdctx);
        st_openssl_die("EVP_DigestSign (taille) a echoue");
    }

    sig = (unsigned char *)st_xmalloc(sig_len);

    if (EVP_DigestSign(mdctx, sig, &sig_len, data, data_len) <= 0) {
        free(sig);
        EVP_MD_CTX_free(mdctx);
        st_openssl_die("EVP_DigestSign a echoue");
    }

    EVP_MD_CTX_free(mdctx);

    out.data = sig;
    out.len = sig_len;
    return out;
}

/*
 * Fonction interne : st_ed25519_verify
 * --------------------------------
 * Rôle :
 *   Vérifier une signature Ed25519.
 *
 * Paramètres :
 *   public_or_private_pkey : clé publique (ou clé contenant aussi la privée)
 *   data                   : données signées
 *   data_len               : longueur des données
 *   sig                    : signature à vérifier
 *   sig_len                : longueur de la signature
 *
 * Retour :
 *   1 si la signature est valide,
 *   0 sinon.
 */
static int st_ed25519_verify(EVP_PKEY *public_or_private_pkey,
                             const unsigned char *data,
                             size_t data_len,
                             const unsigned char *sig,
                             size_t sig_len) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    int rc;

    if (!mdctx) {
        st_openssl_die("EVP_MD_CTX_new a echoue");
    }

    if (EVP_DigestVerifyInit(mdctx, NULL, NULL, NULL, public_or_private_pkey) <= 0) {
        EVP_MD_CTX_free(mdctx);
        st_openssl_die("EVP_DigestVerifyInit a echoue");
    }

    rc = EVP_DigestVerify(mdctx, sig, sig_len, data, data_len);
    EVP_MD_CTX_free(mdctx);

    return rc == 1;
}

/*
 * Fonction interne : st_ed25519_public_from_raw
 * --------------------------------
 * Rôle :
 *   Reconstruire un EVP_PKEY public à partir d’une clé publique brute.
 *
 * Paramètres :
 *   pubkey     : clé publique brute
 *   pubkey_len : longueur
 *
 * Retour :
 *   Un EVP_PKEY* représentant la clé publique.
 *
 * Utilité :
 *   Nécessaire pour vérifier les signatures lorsque l’on ne veut utiliser
 *   que la clé publique brute stockée dans la structure.
 */
static EVP_PKEY *st_ed25519_public_from_raw(const unsigned char *pubkey, size_t pubkey_len) {
    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pubkey, pubkey_len);
    if (!pkey) {
        st_openssl_die("EVP_PKEY_new_raw_public_key a echoue");
    }
    return pkey;
}

/* ============================================================
 * CREATION / CONSTRUCTION
 * ============================================================
 */

/*
 * Fonction : st_create_node
 * --------------------------------
 * Rôle :
 *   Créer un nouveau nœud avec une paire de clés Ed25519 fraîche.
 *
 * Retour :
 *   Pointeur vers le nœud créé.
 *
 * Effet :
 *   - génère la paire de clés,
 *   - extrait la clé publique brute,
 *   - initialise les buffers,
 *   - initialise children et leaves à vide.
 */
ST_SignatureNode *st_create_node(void) {
    ST_SignatureNode *node = (ST_SignatureNode *)st_xcalloc(1, sizeof(ST_SignatureNode));

    node->pkey = st_generate_ed25519_key();
    st_extract_raw_public_key(node->pkey, node->pubkey, &node->pubkey_len);

    st_buffer_init(&node->auth_from_parent);
    node->has_parent_auth = 0;

    node->children = NULL;
    node->nb_children = 0;

    node->leaves = NULL;
    node->nb_leaves = 0;

    return node;
}

/*
 * Fonction : st_add_child
 * --------------------------------
 * Rôle :
 *   Ajouter un fils à un nœud parent.
 *
 * Paramètre :
 *   parent : nœud parent
 *
 * Retour :
 *   Pointeur vers le fils créé.
 *
 * Effet :
 *   - crée un nouveau fils avec sa propre paire de clés,
 *   - signe la clé publique brute du fils avec la clé privée du parent,
 *   - ajoute le fils dans le tableau children.
 */
ST_SignatureNode *st_add_child(ST_SignatureNode *parent) {
    ST_SignatureNode *child = st_create_node();

    child->auth_from_parent = st_ed25519_sign(parent->pkey, child->pubkey, child->pubkey_len);
    child->has_parent_auth = 1;

    parent->children = (ST_SignatureNode **)st_xrealloc(
        parent->children,
        (parent->nb_children + 1) * sizeof(ST_SignatureNode *)
    );

    parent->children[parent->nb_children] = child;
    parent->nb_children++;

    return child;
}

/*
 * Fonction : st_add_message_leaves
 * --------------------------------
 * Rôle :
 *   Ajouter t feuilles terminales à un nœud.
 *
 * Paramètres :
 *   node     : nœud qui devient terminal
 *   t        : nombre de feuilles/messages
 *   messages : tableau de messages
 *
 * Effet :
 *   Crée t feuilles, chacune contenant :
 *   - un message,
 *   - une signature vide,
 *   - le statut "non utilisé".
 */
void st_add_message_leaves(ST_SignatureNode *node, size_t t, const char *messages[]) {
    node->leaves = (ST_MessageLeaf *)st_xcalloc(t, sizeof(ST_MessageLeaf));
    node->nb_leaves = t;

    for (size_t i = 0; i < t; i++) {
        strncpy(node->leaves[i].message, messages[i], ST_MAX_MSG_LEN - 1);
        node->leaves[i].message[ST_MAX_MSG_LEN - 1] = '\0';
        st_buffer_init(&node->leaves[i].sig);
        node->leaves[i].used = 0;
    }
}

/*
 * Fonction : st_build_tree
 * --------------------------------
 * Rôle :
 *   Construire récursivement l’arbre de signature.
 *
 * Paramètres :
 *   node     : racine du sous-arbre courant
 *   depth    : profondeur restante
 *   t        : facteur de branchement
 *   messages : messages à mettre dans chaque nœud terminal
 *
 * Logique :
 *   - si depth == 1 :
 *       le nœud courant est terminal, on lui ajoute t feuilles
 *   - sinon :
 *       on lui ajoute t fils, puis on continue récursivement
 *       sur chacun des fils
 */
void st_build_tree(ST_SignatureNode *node, size_t depth, size_t t, const char *messages[]) {
    if (depth == 0) {
        fprintf(stderr, "Erreur: depth doit etre >= 1\n");
        exit(EXIT_FAILURE);
    }

    if (depth == 1) {
        st_add_message_leaves(node, t, messages);
        return;
    }

    for (size_t i = 0; i < t; i++) {
        ST_SignatureNode *child = st_add_child(node);
        st_build_tree(child, depth - 1, t, messages);
    }
}

/* ============================================================
 * AFFICHAGE / STATS
 * ============================================================
 */

/*
 * Fonction : st_print_tree
 * --------------------------------
 * Rôle :
 *   Afficher récursivement tout l’arbre à partir du nœud donné.
 *
 * Paramètres :
 *   node  : nœud à afficher
 *   level : niveau courant dans l’arbre
 *
 * Effet :
 *   Affiche :
 *   - le niveau,
 *   - le nombre de fils,
 *   - le nombre de feuilles,
 *   - un aperçu de la clé publique,
 *   - les signatures d’authentification éventuelles,
 *   - les feuilles terminales.
 */
void st_print_tree(const ST_SignatureNode *node, size_t level) {
    st_print_indent(level);
    printf("Node(level=%zu, children=%zu, leaves=%zu, pk=",
           level, node->nb_children, node->nb_leaves);
    st_print_hex_prefix(node->pubkey, node->pubkey_len, 8);
    printf(")\n");

    if (node->has_parent_auth) {
        st_print_indent(level + 1);
        printf("auth_from_parent=");
        st_print_hex_prefix(node->auth_from_parent.data, node->auth_from_parent.len, 8);
        printf("\n");
    }

    for (size_t i = 0; i < node->nb_leaves; i++) {
        st_print_indent(level + 1);
        printf("Leaf[%zu]: msg=\"%s\", used=%d",
               i, node->leaves[i].message, node->leaves[i].used);
        if (node->leaves[i].used) {
            printf(", sig=");
            st_print_hex_prefix(node->leaves[i].sig.data, node->leaves[i].sig.len, 8);
        }
        printf("\n");
    }

    for (size_t i = 0; i < node->nb_children; i++) {
        st_print_tree(node->children[i], level + 1);
    }
}

/*
 * Fonction : st_count_total_nodes
 * --------------------------------
 * Rôle :
 *   Compter récursivement le nombre total de nœuds.
 *
 * Paramètre :
 *   node : racine du sous-arbre
 *
 * Retour :
 *   Nombre total de nœuds du sous-arbre.
 */
size_t st_count_total_nodes(const ST_SignatureNode *node) {
    size_t total = 1;
    for (size_t i = 0; i < node->nb_children; i++) {
        total += st_count_total_nodes(node->children[i]);
    }
    return total;
}

/*
 * Fonction : st_count_total_leaves
 * --------------------------------
 * Rôle :
 *   Compter récursivement le nombre total de feuilles-message.
 *
 * Paramètre :
 *   node : racine du sous-arbre
 *
 * Retour :
 *   Nombre total de feuilles.
 */
size_t st_count_total_leaves(const ST_SignatureNode *node) {
    size_t total = node->nb_leaves;
    for (size_t i = 0; i < node->nb_children; i++) {
        total += st_count_total_leaves(node->children[i]);
    }
    return total;
}

/*
 * Fonction : st_count_signed_leaves
 * --------------------------------
 * Rôle :
 *   Compter récursivement le nombre de feuilles déjà signées.
 *
 * Paramètre :
 *   node : racine du sous-arbre
 *
 * Retour :
 *   Nombre total de feuilles utilisées.
 */
size_t st_count_signed_leaves(const ST_SignatureNode *node) {
    size_t total = 0;

    for (size_t i = 0; i < node->nb_leaves; i++) {
        if (node->leaves[i].used) {
            total++;
        }
    }

    for (size_t i = 0; i < node->nb_children; i++) {
        total += st_count_signed_leaves(node->children[i]);
    }

    return total;
}

/* ============================================================
 * SIGNATURE DU PROCHAIN MESSAGE
 * ============================================================
 */

/*
 * Fonction interne : st_sign_next_message_rec
 * --------------------------------
 * Rôle :
 *   Parcourir récursivement l’arbre pour trouver la première feuille
 *   libre, la signer, et construire le résultat complet.
 *
 * Paramètres :
 *   node        : nœud courant
 *   path_nodes  : tableau temporaire des nœuds du chemin
 *   path_indexes: tableau temporaire des indices de fils
 *   depth       : profondeur courante
 *   result      : structure résultat à remplir
 *
 * Retour :
 *   1 si un message a été signé,
 *   0 sinon.
 *
 * Logique :
 *   - si le nœud est terminal :
 *       on cherche la première feuille non utilisée
 *   - sinon :
 *       on explore récursivement les fils dans l’ordre
 */
static int st_sign_next_message_rec(ST_SignatureNode *node,
                                    ST_SignatureNode **path_nodes,
                                    size_t *path_indexes,
                                    size_t depth,
                                    ST_SignResult *result) {
    path_nodes[depth] = node;

    if (node->nb_leaves > 0) {
        for (size_t i = 0; i < node->nb_leaves; i++) {
            if (!node->leaves[i].used) {
                node->leaves[i].sig = st_ed25519_sign(
                    node->pkey,
                    (const unsigned char *)node->leaves[i].message,
                    strlen(node->leaves[i].message)
                );
                node->leaves[i].used = 1;

                result->success = 1;
                strncpy(result->message, node->leaves[i].message, ST_MAX_MSG_LEN - 1);
                result->message[ST_MAX_MSG_LEN - 1] = '\0';

                result->message_signature.data =
                    (unsigned char *)st_xmalloc(node->leaves[i].sig.len);
                memcpy(result->message_signature.data,
                       node->leaves[i].sig.data,
                       node->leaves[i].sig.len);
                result->message_signature.len = node->leaves[i].sig.len;

                result->leaf_index = i;
                result->path_len = depth + 1;

                for (size_t k = 0; k < result->path_len; k++) {
                    result->path_nodes[k] = path_nodes[k];
                }
                for (size_t k = 0; k + 1 < result->path_len; k++) {
                    result->path_child_indexes[k] = path_indexes[k];
                }

                return 1;
            }
        }
        return 0;
    }

    for (size_t i = 0; i < node->nb_children; i++) {
        path_indexes[depth] = i;
        if (st_sign_next_message_rec(node->children[i],
                                     path_nodes,
                                     path_indexes,
                                     depth + 1,
                                     result)) {
            return 1;
        }
    }

    return 0;
}

/*
 * Fonction : st_sign_next_message
 * --------------------------------
 * Rôle :
 *   Signer le prochain message libre dans l’arbre.
 *
 * Paramètres :
 *   root      : racine de l’arbre
 *   max_depth : profondeur maximale d’un chemin
 *
 * Retour :
 *   Un ST_SignResult contenant :
 *   - le message signé,
 *   - sa signature,
 *   - le chemin complet,
 *   - success = 0 si plus rien n’est disponible.
 *
 * Remarque :
 *   Cette fonction alloue des tableaux dynamiques dans le résultat,
 *   qui devront être libérés avec st_free_sign_result().
 */
ST_SignResult st_sign_next_message(ST_SignatureNode *root, size_t max_depth) {
    ST_SignResult result;

    result.success = 0;
    result.message[0] = '\0';
    st_buffer_init(&result.message_signature);
    result.path_len = 0;
    result.leaf_index = 0;

    result.path_nodes = (ST_SignatureNode **)st_xmalloc(max_depth * sizeof(ST_SignatureNode *));
    result.path_child_indexes = (size_t *)st_xmalloc(max_depth * sizeof(size_t));

    ST_SignatureNode **tmp_nodes =
        (ST_SignatureNode **)st_xmalloc(max_depth * sizeof(ST_SignatureNode *));
    size_t *tmp_indexes = (size_t *)st_xmalloc(max_depth * sizeof(size_t));

    int ok = st_sign_next_message_rec(root, tmp_nodes, tmp_indexes, 0, &result);

    free(tmp_nodes);
    free(tmp_indexes);

    if (!ok) {
        result.success = 0;
    }

    return result;
}

/*
 * Fonction : st_free_sign_result
 * --------------------------------
 * Rôle :
 *   Libérer les ressources allouées dans un résultat de signature.
 *
 * Paramètre :
 *   res : résultat à nettoyer
 *
 * Retour :
 *   Aucun.
 */
void st_free_sign_result(ST_SignResult *res) {
    if (!res) return;
    st_buffer_free(&res->message_signature);
    free(res->path_nodes);
    free(res->path_child_indexes);
    res->path_nodes = NULL;
    res->path_child_indexes = NULL;
}

/* ============================================================
 * VERIFICATION
 * ============================================================
 */

/*
 * Fonction : st_verify_sign_result
 * --------------------------------
 * Rôle :
 *   Vérifier qu’un résultat de signature est cohérent et valide.
 *
 * Paramètre :
 *   res : résultat à vérifier
 *
 * Retour :
 *   1 si la vérification réussit,
 *   0 sinon.
 *
 * Vérifications effectuées :
 *   1) pour chaque arête parent -> enfant :
 *      on vérifie que la clé publique de l’enfant a bien été signée
 *      par la clé publique du parent ;
 *   2) on vérifie ensuite la signature finale du message
 *      par la clé publique du nœud terminal.
 */
int st_verify_sign_result(const ST_SignResult *res) {
    if (!res || !res->success || res->path_len == 0) {
        return 0;
    }

    for (size_t i = 0; i + 1 < res->path_len; i++) {
        const ST_SignatureNode *parent = res->path_nodes[i];
        const ST_SignatureNode *child = res->path_nodes[i + 1];

        if (!child->has_parent_auth) {
            return 0;
        }

        EVP_PKEY *parent_pub = st_ed25519_public_from_raw(parent->pubkey, parent->pubkey_len);

        int ok = st_ed25519_verify(parent_pub,
                                   child->pubkey,
                                   child->pubkey_len,
                                   child->auth_from_parent.data,
                                   child->auth_from_parent.len);

        EVP_PKEY_free(parent_pub);

        if (!ok) {
            return 0;
        }
    }

    const ST_SignatureNode *terminal = res->path_nodes[res->path_len - 1];
    EVP_PKEY *terminal_pub = st_ed25519_public_from_raw(terminal->pubkey, terminal->pubkey_len);

    int ok = st_ed25519_verify(terminal_pub,
                               (const unsigned char *)res->message,
                               strlen(res->message),
                               res->message_signature.data,
                               res->message_signature.len);

    EVP_PKEY_free(terminal_pub);
    return ok;
}

/* ============================================================
 * LIBERATION MEMOIRE
 * ============================================================
 */

/*
 * Fonction : st_free_tree
 * --------------------------------
 * Rôle :
 *   Libérer récursivement tout l’arbre.
 *
 * Paramètre :
 *   node : racine du sous-arbre à libérer
 *
 * Effet :
 *   - libère tous les sous-arbres fils,
 *   - libère les signatures des feuilles,
 *   - libère les buffers d’authentification,
 *   - libère la clé OpenSSL,
 *   - libère enfin le nœud lui-même.
 */
void st_free_tree(ST_SignatureNode *node) {
    if (!node) return;

    for (size_t i = 0; i < node->nb_children; i++) {
        st_free_tree(node->children[i]);
    }

    for (size_t i = 0; i < node->nb_leaves; i++) {
        st_buffer_free(&node->leaves[i].sig);
    }

    free(node->children);
    free(node->leaves);

    st_buffer_free(&node->auth_from_parent);

    if (node->pkey) {
        EVP_PKEY_free(node->pkey);
    }

    free(node);
}