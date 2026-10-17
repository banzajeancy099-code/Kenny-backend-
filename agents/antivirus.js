// agents/antivirus.js
const BLACKLIST_COMMANDES = [
  /rm\s+-rf\s+\//, /rm\s+-rf\s+\/\*/, /rm\s+-rf\s+~\//,
  /mkfs/, /dd\s+if=/, /:\(\)\s*\{\s*:\|:&\s*\};:/,
  /^sudo\s+/, /^su\s+/, /chmod\s+777\s+\//, /chown\s+root/,
  /nc\s+-e/, /ncat\s+-e/, /bash\s+-i\s+>&/, /\/dev\/tcp\//,
  /cat\s+.*\.ssh\//, /cat\s+.*\.aws\//, /cat\s+.*\.env/,
  /cat\s+.*\.git-credentials/, /cat\s+.*\/etc\/passwd/, /cat\s+.*\/etc\/shadow/,
  /curl\s+.*\|\s*bash/, /curl\s+.*\|\s*sh/, /wget\s+.*\|\s*bash/, /wget\s+.*\|\s*sh/,
  /xmrig/, /minerd/,
];

const WHITELIST_DOMAINES = [
  'github.com', 'raw.githubusercontent.com', 'registry.npmjs.org', 
  'npmjs.com', 'pypi.org', 'files.pythonhosted.org', 'nodejs.org',
  'deb.debian.org', 'archive.ubuntu.com',
];

const CHEMINS_PROTEGES = [
  '/etc/', '/root/', '/home/other/', '/var/www/', '/opt/kenny/',
  '~/.ssh/', '~/.aws/', '~/.config/',
];

const PATTERNS_SUSPECTS = [
  /\$\(.*\)/, /`.*`/, /\beval\b/, /\bexec\b/, />\s*\/dev\/sd/,
  /\bcurl\s+(?![^|]*\b(?:github|npmjs|pypi|pythonhosted|nodejs|debian|ubuntu)\.)/,
  /\bwget\s+(?![^|]*\b(?:github|npmjs|pypi|pythonhosted|nodejs|debian|ubuntu)\.)/,
];

function verifierCommande(commande, mode = 'normal') {
  const cmd = commande.trim();
  if (!cmd) return { allowed: false, level: 'error', reason: 'Commande vide' };

  if (mode === 'libre') {
    for (const pattern of BLACKLIST_COMMANDES) {
      if (pattern.test(cmd)) return { allowed: false, level: 'danger', reason: `🚨 Commande critique bloquée : ${pattern.source}`, needsConfirmation: false };
    }
    return { allowed: true, level: 'info', reason: 'Mode libre' };
  }

  for (const pattern of BLACKLIST_COMMANDES) {
    if (pattern.test(cmd)) return { allowed: false, level: 'danger', reason: `🚫 Commande dangereuse détectée.`, needsConfirmation: false };
  }

  if (/\b(curl|wget)\b/.test(cmd)) {
    const domainesAutorises = WHITELIST_DOMAINES.some(d => cmd.includes(d));
    if (!domainesAutorises) return { allowed: false, level: 'warning', reason: `⚠️ Domaine non autorisé.`, needsConfirmation: true };
  }

  for (const chemin of CHEMINS_PROTEGES) {
    if (cmd.includes(chemin)) return { allowed: false, level: 'danger', reason: `🚫 Accès au chemin protégé : ${chemin}`, needsConfirmation: false };
  }

  for (const pattern of PATTERNS_SUSPECTS) {
    if (pattern.test(cmd)) {
      if (mode === 'strict') return { allowed: false, level: 'warning', reason: `⚠️ Commande suspecte (mode strict).`, needsConfirmation: true };
      return { allowed: true, level: 'warning', reason: `⚠️ Commande suspecte, mais autorisée.`, needsConfirmation: true };
    }
  }

  return { allowed: true, level: 'info', reason: '✅ Commande validée', needsConfirmation: false };
}

function nettoyerCommande(commande) {
  return commande.replace(/[\x00-\x1F\x7F]/g, '').trim();
}

module.exports = { verifierCommande, nettoyerCommande };
