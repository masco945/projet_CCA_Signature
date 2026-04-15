#include <stdio.h>
#include "signature_tree_openssl.h"

/*
 * ============================================================
 * Fichier : main.c
 * ============================================================
 *
 * Rôle :
 *   Ce fichier montre un exemple d’utilisation du module
 *   signature_tree_openssl.
 *
 * Ce que fait ce programme :
 *   1) initialise OpenSSL,
 *   2) crée la racine de l’arbre,
 *   3) construit un arbre t-aire de profondeur donnée,
 *   4) affiche l’arbre initial,
 *   5) signe plusieurs messages successivement,
 *   6) vérifie chaque signature produite,
 *   7) affiche l’état final de l’arbre,
 *   8) libère toute la mémoire.
 */

int main(void) {
    /*
     * Initialisation de la bibliothèque OpenSSL.
     * Doit être faite avant les opérations cryptographiques.
     */
    st_openssl_init();

    /*
     * t :
     *   facteur de branchement de l’arbre.
     *   Chaque nœud interne aura exactement t fils.
     *
     * depth :
     *   profondeur en nombre de niveaux de nœuds.
     *
     * Exemple :
     *   depth = 3, t = 3
     *   -> niveau 0 : 1 racine
     *   -> niveau 1 : 3 fils
     *   -> niveau 2 : 9 nœuds terminaux
     *   -> chaque nœud terminal contient 3 feuilles-message
     */
    const size_t t = 3;
    const size_t depth = 3;

    /*
     * Tableau de messages utilisé dans chaque nœud terminal.
     * Comme t = 3, il faut fournir exactement 3 messages.
     */
    const char *messages[] = {
        "message_1",
        "message_2",
        "message_3"
    };

    /*
     * Création de la racine.
     * Cette fonction génère automatiquement une paire de clés Ed25519.
     */
    ST_SignatureNode *root = st_create_node();

    /*
     * Construction récursive de tout l’arbre.
     */
    st_build_tree(root, depth, t, messages);

    /*
     * Affichage initial de l’arbre.
     */
    printf("===== ARBRE INITIAL =====\n");
    st_print_tree(root, 0);

    /*
     * Affichage de quelques statistiques globales.
     */
    printf("\nStats initiales:\n");
    printf("- total nodes   : %zu\n", st_count_total_nodes(root));
    printf("- total leaves  : %zu\n", st_count_total_leaves(root));
    printf("- signed leaves : %zu\n", st_count_signed_leaves(root));

    /*
     * On tente ici de signer 5 messages successifs.
     * À chaque tour :
     *   - on récupère le prochain message libre,
     *   - on le signe,
     *   - on vérifie le chemin complet,
     *   - on libère ensuite le résultat.
     */
    printf("\n===== SIGNATURES =====\n");
    for (int i = 0; i < 5; i++) {
        ST_SignResult res = st_sign_next_message(root, depth);

        /*
         * Si success == 0, cela signifie qu’il n’existe plus
         * aucun message non signé dans l’arbre.
         */
        if (!res.success) {
            printf("Plus aucun message disponible.\n");
            st_free_sign_result(&res);
            break;
        }

        printf("Signature #%d\n", i + 1);
        printf("  message      : %s\n", res.message);
        printf("  leaf_index   : %zu\n", res.leaf_index);
        printf("  path_len     : %zu\n", res.path_len);

        /*
         * Vérification cryptographique complète :
         *   - authentification des clés publiques le long du chemin
         *   - vérification de la signature finale du message
         */
        printf("  verification : %s\n",
               st_verify_sign_result(&res) ? "OK" : "ECHEC");

        /*
         * Important :
         * le résultat contient de la mémoire dynamique,
         * donc il faut le libérer après usage.
         */
        st_free_sign_result(&res);
    }

    /*
     * Affichage de l’arbre après plusieurs signatures.
     */
    printf("\n===== ARBRE FINAL =====\n");
    st_print_tree(root, 0);

    /*
     * Libération complète de l’arbre.
     */
    st_free_tree(root);

    /*
     * Nettoyage final d’OpenSSL.
     */
    st_openssl_cleanup();
    return 0;
}