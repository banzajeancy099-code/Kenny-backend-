// ============================================
// 🧠 MÉMOIRE SÉMANTIQUE — Agent
// ============================================

const axios = require('axios');
const pgvector = require('pgvector/pg');

// Détecte le contexte d'un fichier
function detecterContexte(fichier, contenu, promptOriginal) {
  const nom = fichier.nom || '';
  const ext = nom.split('.').pop()?.toLowerCase();
  const c = (contenu || '').toLowerCase();
  const p = (promptOriginal || '').toLowerCase();

  let langage = 'unknown';
  if (ext === 'py' || c.includes('import ') || c.includes('from ')) langage = 'python';
  else if (ext === 'js' || c.includes('require(') || c.includes('const ')) langage = 'javascript';
  else if (ext === 'html') langage = 'html';
  else if (ext === 'css') langage = 'css';
  else if (ext === 'json') langage = 'json';

  let framework = null;
  if (langage === 'python') {
    if (c.includes('from flask') || c.includes('import flask')) framework = 'flask';
    else if (c.includes('from fastapi') || c.includes('import fastapi')) framework = 'fastapi';
    else if (c.includes('from django') || c.includes('import django')) framework = 'django';
  } else if (langage === 'javascript') {
    if (c.includes('express')) framework = 'express';
    else if (c.includes('react')) framework = 'react';
    else if (c.includes('vue')) framework = 'vue';
  }

  let domaine = 'generic';
  if (/(auth|login|register|session|jwt|password)/.test(p)) domaine = 'auth';
  else if (/(api|rest|endpoint|route)/.test(p)) domaine = 'api_rest';
  else if (/(database|sql|postgres|sqlite|model)/.test(p)) domaine = 'database';
  else if (/(frontend|ui|template|html|css)/.test(p)) domaine = 'frontend';
  else if (/(football|sport|pronostic|bet|kelly)/.test(p)) domaine = 'football';
  else if (/(ecommerce|shop|cart|product)/.test(p)) domaine = 'ecommerce';
  else if (/(chatbot|chat|llm|ia)/.test(p)) domaine = 'chatbot';
  else if (/(scrap|crawl|fetch)/.test(p)) domaine = 'scraping';

  return { langage, framework, domaine, taille_projet: 'medium' };
}

// Classifie une erreur
function classifierErreur(erreur) {
  if (/SyntaxError|IndentationError|TabError/.test(erreur)) return 'syntax';
  if (/ModuleNotFoundError|ImportError|cannot import/.test(erreur)) return 'import';
  if (/NameError|TypeError|ValueError|KeyError|AttributeError|IndexError/.test(erreur)) return 'logic';
  if (/pip|install|package|npm ERR/.test(erreur)) return 'dependency';
  if (/ConnectionError|TimeoutError|refused/.test(erreur)) return 'network';
  return 'logic';
}

// Génère un embedding via Gemini
async function genererEmbedding(texte, geminiKey) {
  if (!geminiKey) return null;
  
  // 🧹 Sanitize
  texte = String(texte || '')
    .replace(/[\u0000-\u001F\u007F-\u009F]/g, ' ')
    .replace(/[\u200B-\u200F\u2028-\u202F\uFEFF]/g, '')
    .substring(0, 8000);
  
  if (!texte || texte.length < 5) {
    console.log('⚠️ Embedding: texte vide après sanitize');
    return null;
  }
  
  try {
    // ✅ Modèle actuel : gemini-embedding-001
    const response = await axios.post(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-embedding-001:embedContent?key=${geminiKey}`,
      {
        model: 'models/gemini-embedding-001',
        content: { parts: [{ text: texte.substring(0, 8000) }] },
        outputDimensionality: 768
      },
      { timeout: 30000 }
    );
    
    let vec = response.data.embedding.values;
    
    // ⚠️ gemini-embedding-001 ne normalise pas automatiquement → L2 normalize
    const norm = Math.sqrt(vec.reduce((s, v) => s + v * v, 0));
    if (norm === 0) return vec;
    return vec.map(v => v / norm);
  } catch (e) {
    console.log('⚠️ Embedding échec:', e.response?.data?.error?.message || e.message);
    return null;
  }
}

// Vérifie la compatibilité contexte
function estCompatible(correction, contexteActuel) {
  if (correction.langage !== contexteActuel.langage) return false;
  if (correction.framework && correction.framework !== contexteActuel.framework) {
    if (correction.framework !== 'generic') return false;
  }
  if (correction.domaine && correction.domaine !== contexteActuel.domaine) {
    if (correction.domaine !== 'generic') return false;
  }
  const tailles = { small: 1, medium: 2, large: 3 };
  const ecart = Math.abs(
    (tailles[correction.taille_projet] || 2) - (tailles[contexteActuel.taille_projet] || 2)
  );
  if (ecart > 1) return false;
  return true;
}

// Validation par IA
async function validerParIA(correction, contexteActuel, geminiKey) {
  if (!geminiKey) return true;
  try {
    const prompt = `Tu valides si une correction passée s'applique au contexte actuel.

CONTEXTE ACTUEL :
- Langage : ${contexteActuel.langage}
- Framework : ${contexteActuel.framework || 'aucun'}
- Domaine : ${contexteActuel.domaine}
- Erreur : ${(contexteActuel.erreur || '').substring(0, 300)}
- Fichier : ${contexteActuel.fichier}

CORRECTION PASSÉE :
- Langage : ${correction.langage}
- Framework : ${correction.framework || 'aucun'}
- Domaine : ${correction.domaine}
- Erreur : ${(correction.erreur_message || '').substring(0, 300)}
- Explication : ${(correction.explication || '').substring(0, 300)}

QUESTION : Cette correction est-elle PERTINENTE pour le contexte actuel ?
Réponds UNIQUEMENT par : OUI ou NON`;

    const response = await axios.post(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent?key=${geminiKey}`,
      {
        contents: [{ role: 'user', parts: [{ text: prompt }] }],
        generationConfig: { temperature: 0.1, maxOutputTokens: 10 }
      },
      { timeout: 15000 }
    );

    const answer = response.data.candidates[0].content.parts[0].text.trim().toUpperCase();
    return answer.startsWith('OUI');
    } catch (e) {
    console.log('⚠️ Embedding échec:', e.response?.data?.error?.message || e.message);
    console.log('⚠️ Embedding status:', e.response?.status);
    console.log('⚠️ Embedding URL:', e.config?.url);
    console.log('⚠️ Embedding body envoyé:', JSON.stringify(e.config?.data).substring(0, 500));
    return null;
  }
}

// Recherche sémantique sécurisée
async function chercherCorrectionsSimilaires(erreur, fichier, contexteActuel, userId, projectId, geminiKey, limit, withPg) {
  try {
    const erreurType = classifierErreur(erreur);
    const embedding = await genererEmbedding(
      `${erreurType}\n${erreur.substring(0, 500)}\n${fichier.nom}`,
      geminiKey
    );
    if (!embedding) return [];

    const candidats = await withPg(async (client) => {
      await pgvector.registerTypes(client);
      const result = await client.query(
        `SELECT 
           id, langage, framework, domaine, taille_projet,
           fichier_coupable, erreur_type, erreur_message,
           code_avant, code_apres, explication,
           succes, reward, used_count,
           embedding <=> $1 AS distance
         FROM kenny_corrections
         WHERE succes = TRUE
           AND reward > 0
           AND echecs_count < 3
           AND (project_id = $2 OR user_id = $3 OR is_global = TRUE)
           AND langage = $4
           AND erreur_type = $5
           AND embedding <=> $1 < 0.15
         ORDER BY embedding <=> $1
         LIMIT $6`,
        [
          pgvector.toSql(embedding),
          projectId, userId,
          contexteActuel.langage,
          erreurType,
          limit * 2
        ]
      );
      return result.rows;
    });

    const compatibles = candidats.filter(c => estCompatible(c, contexteActuel));
    if (compatibles.length === 0) return [];

    const valides = [];
    for (const c of compatibles.slice(0, 3)) {
      const ok = await validerParIA(c, { ...contexteActuel, erreur, fichier: fichier.nom }, geminiKey);
      if (ok) valides.push(c);
      if (valides.length >= limit) break;
    }

    if (valides.length > 0) {
      await withPg(async (client) => {
        await client.query(
          `UPDATE kenny_corrections SET used_count = used_count + 1 WHERE id = ANY($1)`,
          [valides.map(c => c.id)]
        );
      });
    }

    return valides;
  } catch (e) {
    console.log('⚠️ Recherche mémoire échec:', e.message);
    return [];
  }
}

// Enregistre une correction
async function enregistrerCorrection(data, geminiKey, withPg) {
  try {
    const { project_id, user_id, fichier, contexte, erreur, codeAvant, codeApres, explication, provider, succes, tentatives } = data;

    const erreurType = classifierErreur(erreur);
    const embedding = await genererEmbedding(
      `${erreurType}\n${erreur.substring(0, 500)}\n${fichier}`,
      geminiKey
    );
    if (!embedding) return false;

    await withPg(async (client) => {
      await pgvector.registerTypes(client);
      const reward = succes ? 1.0 : -0.5;

      await client.query(
        `INSERT INTO kenny_corrections 
         (project_id, user_id, langage, framework, domaine, taille_projet,
          fichier_coupable, erreur_type, erreur_message,
          code_avant, code_apres, explication, provider,
          succes, reward, tentatives, embedding)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`,
        [
          project_id, user_id,
          contexte.langage, contexte.framework, contexte.domaine, contexte.taille_projet,
          fichier, erreurType, erreur.substring(0, 2000),
          codeAvant?.substring(0, 5000), codeApres?.substring(0, 5000),
          explication?.substring(0, 1000), provider,
          succes, reward, tentatives,
          pgvector.toSql(embedding)
        ]
      );
    });

    return true;
  } catch (e) {
    console.log('⚠️ Enregistrement mémoire échec:', e.message);
    return false;
  }
}

// Pénalise une correction qui n'a pas marché
async function penaliserCorrection(correctionIds, withPg) {
  if (!correctionIds || correctionIds.length === 0) return;
  try {
    await withPg(async (client) => {
      await client.query(
        `UPDATE kenny_corrections 
         SET reward = reward - 0.5,
             echecs_count = echecs_count + 1
         WHERE id = ANY($1)`,
        [correctionIds]
      );
    });
  } catch (e) {
    console.log('⚠️ Pénalisation échec:', e.message);
  }
}

module.exports = {
  detecterContexte,
  classifierErreur,
  genererEmbedding,
  chercherCorrectionsSimilaires,
  enregistrerCorrection,
  penaliserCorrection
};
