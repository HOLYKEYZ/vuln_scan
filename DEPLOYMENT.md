# Deploying to Render

This guide will help you deploy the Vulnerability Scanner web application to Render.

## Prerequisites

- A [Render account](https://render.com) (free tier available)
- Your code pushed to a GitHub repository
- API keys for LLM providers (optional, but recommended for full functionality)

## Quick Deploy (Using Render Blueprint)

1. **Push your code to GitHub** (if not already done)

2. **Go to Render Dashboard**
   - Visit https://dashboard.render.com
   - Click "New" → "Blueprint"

3. **Connect your repository**
   - Select your GitHub repository
   - Render will automatically detect the `render.yaml` file

4. **Configure Environment Variables**
   
   Add your LLM API keys in the Render dashboard:
   
   | Variable Name | Description | Required |
   |--------------|-------------|----------|
   | `GOOGLE_API_KEY` | Google Gemini API key | Optional |
   | `OPENAI_API_KEY` | OpenAI GPT API key | Optional |
   | `ANTHROPIC_API_KEY` | Anthropic Claude API key | Optional |
   | `GROQ_KEY` | Groq API key | Optional |
   
   **Note:** The app will work without API keys (AST-only mode), but LLM analysis will be disabled.

5. **Deploy**
   - Click "Apply" to deploy
   - Wait for the build to complete (usually 2-5 minutes)
   - Your app will be live at `https://your-service-name.onrender.com`

## Manual Deploy (Alternative Method)

If you prefer not to use the Blueprint:

1. **Create a New Web Service**
   - Go to Render Dashboard → "New" → "Web Service"
   - Connect your GitHub repository

2. **Configure Build Settings**
   - **Name:** `vulnerability-scanner` (or your preferred name)
   - **Environment:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn web_dashboard.app:app --bind 0.0.0.0:$PORT`

3. **Add Environment Variables** (same as above)

4. **Deploy**

## Getting Your API Keys

### Google Gemini (Recommended - Free Tier Available)
1. Go to [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Click "Get API Key"
3. Copy the key and add it as `GOOGLE_API_KEY` in Render

### OpenAI
1. Go to [OpenAI API Keys](https://platform.openai.com/api-keys)
2. Create a new API key
3. Add it as `OPENAI_API_KEY` in Render

### Anthropic Claude
1. Go to [Anthropic Console](https://console.anthropic.com/)
2. Generate an API key
3. Add it as `ANTHROPIC_API_KEY` in Render

### Groq (Free & Fast)
1. Go to [Groq Console](https://console.groq.com/)
2. Create an API key
3. Add it as `GROQ_KEY` in Render

## Testing Your Deployment

1. Visit your Render URL
2. Upload a Python file (you can use any `.py` file from this project)
3. Select analysis mode:
   - **AST Static Analysis** - Works without API keys
   - **LLM Deep Analysis** - Requires API key
   - **Hybrid** - Best results (requires API key)
4. Click "INITIATE SCAN"
5. Review the results

## Troubleshooting

### Build Fails
- Check that `requirements.txt` is in the root directory
- Verify Python version compatibility (3.11+ recommended)

### App Crashes on Start
- Check Render logs for error messages
- Verify the start command is correct
- Ensure `web_dashboard/app.py` exists

### LLM Analysis Not Working
- Verify API keys are set correctly in Render environment variables
- Check that the key names match exactly (case-sensitive)
- Test with AST-only mode first to isolate the issue

### Upload Not Working
- Check file size (max 16MB)
- Ensure file has `.py` extension
- Check Render logs for errors

## Cost Considerations

- **Render Free Tier:** Your app will sleep after 15 minutes of inactivity
- **LLM API Costs:**
  - Gemini: Free tier available (15 requests/minute)
  - Groq: Free tier available (fast inference)
  - OpenAI: Pay-per-use (check pricing)
  - Claude: Pay-per-use (check pricing)

## Updating Your Deployment

Render automatically redeploys when you push to your GitHub repository's main branch.

To manually redeploy:
1. Go to your service in Render Dashboard
2. Click "Manual Deploy" → "Deploy latest commit"

## Support

For issues specific to:
- **Render deployment:** Check [Render docs](https://render.com/docs)
- **Application bugs:** Check your repository issues
- **API keys:** Contact the respective provider's support
