import openai

OPENAI_API_KEY = "your-openai-api-key"

def summarize_text(text):
    """Summarizes extracted text using OpenAI GPT-4."""
    if len(text.split()) < 50:  # If text is too short, return as is
        return text.strip()

    try:
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are an AI assistant that summarizes text."},
                {"role": "user", "content": f"Summarize this text:\n\n{text}"}
            ],
            max_tokens=100
        )
        summary = response["choices"][0]["message"]["content"].strip()
        print(f"AI Summary:\n{summary}\n{'-'*50}")
        return summary

    except Exception as e:
        print(f"OpenAI API Error: {e}")
        return "Summarization failed"