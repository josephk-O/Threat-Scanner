import google.generativeai as genai
import os
from dotenv import load_dotenv

load_dotenv()

def setup_gemini():
    """Setup Gemini AI with API key"""
    api_key = os.getenv('GEMINI_API_KEY')
    if not api_key:
        raise ValueError("Gemini API key not found in .env file")
    genai.configure(api_key=api_key)
    
    # Use the updated model name (gemini-1.5-pro instead of gemini-pro)
    try:
        # Try the newer model first
        return genai.GenerativeModel('gemini-1.5-pro')
    except Exception as e:
        # Fall back to older model if available
        try:
            return genai.GenerativeModel('gemini-pro')
        except Exception as nested_e:
            # If both fail, provide a detailed error
            raise ValueError(f"Could not initialize Gemini AI model. Error with gemini-1.5-pro: {str(e)}. Error with gemini-pro: {str(nested_e)}")

def analyze_results(scan_results):
    """Analyze scan results using Gemini AI"""
    try:
        model = setup_gemini()
        
        # Prepare the prompt
        prompt = f"""
        Analyze these network security scan results and provide:
        1. Key security insights
        2. Risk assessment (High/Medium/Low) for each IP
        3. Recommended actions
        4. Any patterns or concerning trends

        Scan Results:
        {scan_results}

        If you need any clarification about specific IPs or results, please indicate what additional information would be helpful.
        """

        # Updated way to generate content
        response = model.generate_content(prompt)
        
        # Check if response has text attribute
        if hasattr(response, 'text'):
            analysis_text = response.text
        elif hasattr(response, 'parts'):
            # Alternative way to get response text
            analysis_text = ''.join([part.text for part in response.parts])
        else:
            # Last resort
            analysis_text = str(response)

        return {
            'analysis': analysis_text,
            'needs_clarification': 'clarification' in analysis_text.lower()
        }

    except Exception as e:
        return {
            'error': f"AI Analysis Error: {str(e)}",
            'needs_clarification': False
        }

def get_clarification(question, additional_info):
    """Get clarification from Gemini about specific aspects"""
    try:
        model = setup_gemini()
        
        prompt = f"""
        Previous question: {question}
        Additional information provided: {additional_info}
        
        Please provide updated analysis with this new information.
        """

        response = model.generate_content(prompt)
        
        # Handle response same way as in analyze_results
        if hasattr(response, 'text'):
            return response.text
        elif hasattr(response, 'parts'):
            return ''.join([part.text for part in response.parts])
        else:
            return str(response)

    except Exception as e:
        return f"Clarification Error: {str(e)}" 