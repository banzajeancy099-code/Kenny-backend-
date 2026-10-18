// agents/antivirus.js
const BLACKLIST_COMMANDES = [
  // Destruction système
  /rm\s+-rf\s+\//, /rm\s+-rf\s+\/\*/, /rm\s+-rf\s+~\//,
  /mkfs/, /dd\s+if=/, /:\(\)\s*\{\s*:\|:&\s*\};:/,
  
  // Élévation de privilèges
  /^sudo\s+/, /^su\s+/, /chmod\s+777\s+\//, /chown\s+root/,
  
  // Réseau dangereux
  /nc\s+-e/, /ncat\s+-e/, /bash\s+-i\s+>&/, /\/dev\/tcp\//,
  
  // Vol de credentials
  /cat\s+.*\.ssh\//, /cat\s+.*\.aws\//, /cat\s+.*\.env/,
  /cat\s+.*\.git-credentials/, /cat\s+.*\/etc\/passwd/, /cat\s+.*\/etc\/shadow/,
  
  // Exfiltration
  /curl\s+.*\|\s*bash/, /curl\s+.*\|\s*sh/, /wget\s+.*\|\s*bash/, /wget\s+.*\|\s*sh/,
  
  // Cryptojacking
  /xmrig/, /minerd/,
  
  // 🔥 apt-get update (bloqué dans la sandbox E2B)
  /^apt-get\s+update/, /^apt\s+update/,
];

const WHITELIST_DOMAINES = [
  'github.com', 'raw.githubusercontent.com', 'registry.npmjs.org', 
  'npmjs.com', 'pypi.org', 'files.pythonhosted.org', 'nodejs.org',
  'deb.debian.org', 'archive.ubuntu.com', 'security.debian.org', 
  'security.ubuntu.com', 'sh.rustup.rs',
];

const CHEMINS_PROTEGES = [
  '/etc/', '/root/', '/home/other/', '/var/www/', '/opt/kenny/',
  '~/.ssh/', '~/.aws/', '~/.config/',
];

const PATTERNS_SUSPECTS = [
  /\$\(.*\)/, /`.*`/, /\beval\b/, /\bexec\b/, />\s*\/dev\/sd/,
  /\bcurl\s+(?![^|]*\b(?:github|npmjs|pypi|pythonhosted|nodejs|debian|ubuntu|rustup)\.)/,
  /\bwget\s+(?![^|]*\b(?:github|npmjs|pypi|pythonhosted|nodejs|debian|ubuntu|rustup)\.)/,
];

// 🔥 Commandes déjà installées (pas besoin de vérifier)
const DEJA_INSTALLEES = [
  /^python3\s/,
  /^python\s/,
  /^node\s/,
  /^npm\s/,
  /^pip\s/,
  /^pip3\s/,
  /^git\s/,
  /^ls/,
  /^pwd/,
  /^cd\s/,
  /^cat\s/,
  /^echo\s/,
  /^mkdir\s/,
  /^touch\s/,
];

function verifierCommande(commande, mode = 'normal') {
  const cmd = commande.trim();
  if (!cmd) return { allowed: false, level: 'error', reason: 'Commande vide' };

  // Blacklist
  for (const pattern of BLACKLIST_COMMANDES) {
    if (pattern.test(cmd)) {
      return { allowed: false, level: 'danger', reason: `🚫 Commande bloquée : ${pattern.source}`, needsConfirmation: false };
    }
  }

  // Mode libre : presque tout passe
  if (mode === 'libre') {
    return { allowed: true, level: 'info', reason: 'Mode libre', needsConfirmation: false };
  }

  // Chemins protégés
  for (const chemin of CHEMINS_PROTEGES) {
    if (cmd.includes(chemin)) {
      return { allowed: false, level: 'danger', reason: `🚫 Accès au chemin protégé : ${chemin}`, needsConfirmation: false };
    }
  }

  // Curl/wget whitelist
  if (/\b(curl|wget)\b/.test(cmd)) {
    const domainesAutorises = WHITELIST_DOMAINES.some(d => cmd.includes(d));
    if (!domainesAutorises) {
      return { allowed: false, level: 'warning', reason: `⚠️ Domaine non autorisé`, needsConfirmation: true };
    }
  }

  // Patterns suspects
  for (const pattern of PATTERNS_SUSPECTS) {
    if (pattern.test(cmd)) {
      if (mode === 'strict') {
        return { allowed: false, level: 'warning', reason: `⚠️ Commande suspecte (strict)`, needsConfirmation: true };
      }
      return { allowed: true, level: 'warning', reason: `⚠️ Commande suspecte autorisée`, needsConfirmation: true };
    }
  }

  return { allowed: true, level: 'info', reason: '✅ Commande validée', needsConfirmation: false };
}

function nettoyerCommande(commande) {
  return commande.replace(/[\x00-\x1F\x7F]/g, '').trim();
}

module.exports = { verifierCommande, nettoyerCommande };
