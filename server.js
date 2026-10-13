// ============================================
// AGENT IMAGE (Cloudflare Workers AI)
// ============================================
const CLOUDFLARE_AI_TOKEN = process.env.CLOUDFLARE_AI_TOKEN;

async function imageAgent(prompt, options = {}) {
  console.log('🎨 Image Agent : début');
  
  try {
    const response = await axios.post(
      `https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/ai/run/@cf/black-forest-labs/flux-1-schnell`,
      {
        prompt: prompt,
        width: options.width || 1024,
        height: options.height || 1024,
        num_steps: 4
      },
      {
        headers: {
          'Authorization': `Bearer ${CLOUDFLARE_AI_TOKEN}`,
          'Content-Type': 'application/json'
        },
        responseType: 'arraybuffer',
        timeout: 60000
      }
    );
    
    const base64 = Buffer.from(response.data).toString('base64');
    const imageUrl = `data:image/png;base64,${base64}`;
    
    console.log('✅ Image générée');
    
    return {
      success: true,
      image_url: imageUrl,
      prompt: prompt
    };
    
  } catch (error) {
    console.error('❌ Image Agent erreur:', error.response?.data || error.message);
    return {
      success: false,
      error: error.response?.data?.message || error.message
    };
  }
}

// Route de génération d'image
app.post('/api/image', async (req, res) => {
  const { prompt, width, height } = req.body;
  
  if (!prompt) {
    return res.status(400).json({ error: 'prompt requis' });
  }
  
  console.log('🎨 Génération image :', prompt);
  
  try {
    const result = await imageAgent(prompt, { width, height });
    
    if (!result.success) {
      return res.status(500).json({ error: result.error });
    }
    
    res.json(result);
    
  } catch (error) {
    console.error('Erreur image:', error);
    res.status(500).json({ error: error.message });
  }
});
