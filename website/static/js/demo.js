document.addEventListener('DOMContentLoaded', () => {
    const trigger = document.getElementById('demo-trigger');
    const landingPage = document.getElementById('landing-page');
    const demoContainer = document.getElementById('demo-container');
    const exitDemoBtn = document.getElementById('exit-demo-btn');
    const chatInput = document.getElementById('chat-input');
    const sendBtn = document.getElementById('send-chat-btn');
    const chatDisplay = document.getElementById('chat-display');
    const aiPromptInput = document.getElementById('demo-ai-prompt');
    const knowledgeBaseInput = document.getElementById('demo-knowledge-base');
    const knowledgeFeedback = document.getElementById('knowledge-feedback');

    // Forms
    const webForm = document.getElementById('demo-web-form');
    const youtubeForm = document.getElementById('demo-youtube-form');
    const pdfForm = document.getElementById('demo-pdf-form');

    // --- Lógica para iniciar y salir de la demo ---

    trigger.addEventListener('click', () => {
        trigger.classList.add('zoomed');
        landingPage.style.opacity = '0';
        setTimeout(() => {
            demoContainer.classList.add('visible');
        }, 500);
    });

    exitDemoBtn.addEventListener('click', () => {
        demoContainer.classList.remove('visible');
        resetDemo();
        setTimeout(() => {
            trigger.classList.remove('zoomed');
            landingPage.style.opacity = '1';
        }, 500);
    });

    function resetDemo() {
        const initialMessage = chatDisplay.querySelector('.chat-message.bot');
        chatDisplay.innerHTML = '';
        chatDisplay.appendChild(initialMessage);
        
        aiPromptInput.value = `Eres Anlios, un asistente de IA amigable. Tu conocimiento se limita a la 'Base de Conocimientos'. Si no sabes la respuesta, dilo amablemente.

--- BASE DE CONOCIMIENTOS ---
{knowledge}`;
        knowledgeBaseInput.value = '';
        knowledgeFeedback.textContent = '';
        webForm.reset();
        youtubeForm.reset();
        pdfForm.reset();
    }

    // --- Lógica del Chat ---

    sendBtn.addEventListener('click', sendMessage);
    chatInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') sendMessage();
    });

    async function sendMessage() {
        const messageText = chatInput.value.trim();
        if (!messageText) return;

        appendMessage(messageText, 'user');
        chatInput.value = '';
        
        const typingIndicator = appendMessage('...', 'bot', true);

        try {
            const response = await fetch('/demo_chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    message: messageText,
                    prompt: aiPromptInput.value,
                    knowledge: knowledgeBaseInput.value,
                }),
            });

            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            const data = await response.json();
            typingIndicator.querySelector('.message-content p').textContent = data.reply;
            typingIndicator.classList.remove('typing');
        } catch (error) {
            console.error('Error fetching chat response:', error);
            typingIndicator.querySelector('.message-content p').textContent = 'Lo siento, hubo un error al conectar con mis circuitos.';
            typingIndicator.classList.add('error');
        }
    }

    function appendMessage(text, type, isTyping = false) {
        const messageWrapper = document.createElement('div');
        messageWrapper.className = `chat-message ${type}`;
        
        const content = document.createElement('div');
        content.className = 'message-content';
        
        const p = document.createElement('p');
        p.textContent = text;
        content.appendChild(p);
        
        if (type === 'bot') {
            const avatar = document.createElement('img');
            avatar.src = '/static/images/hablando.gif';
            avatar.alt = 'Bot hablando';
            avatar.className = 'bot-avatar';
            messageWrapper.appendChild(avatar);
        }
        
        if(isTyping) messageWrapper.classList.add('typing');

        messageWrapper.appendChild(content);
        chatDisplay.appendChild(messageWrapper);
        chatDisplay.scrollTop = chatDisplay.scrollHeight;
        return messageWrapper;
    }

    // --- Lógica para añadir conocimiento ---

    async function handleKnowledgeForm(event, sourceType) {
        event.preventDefault();
        const form = event.target;
        const submitButton = form.querySelector('button[type="submit"]');
        const originalButtonText = submitButton.textContent;
        
        submitButton.disabled = true;
        submitButton.textContent = 'Cargando...';
        knowledgeFeedback.textContent = 'Extrayendo información...';
        knowledgeFeedback.style.color = '#ffb3b3';

        const formData = new FormData(form);
        formData.append('source_type', sourceType);

        try {
            const response = await fetch('/demo_extract_knowledge', {
                method: 'POST',
                body: formData,
            });
            
            const data = await response.json();

            if (data.success) {
                knowledgeBaseInput.value += (knowledgeBaseInput.value ? '\n\n' : '') + data.text;
                knowledgeFeedback.textContent = '¡Información añadida con éxito!';
                knowledgeFeedback.style.color = '#28a745';
                form.reset();
            } else {
                throw new Error(data.error || 'Ocurrió un error desconocido.');
            }

        } catch (error) {
            console.error(`Error extracting from ${sourceType}:`, error);
            knowledgeFeedback.textContent = `Error: ${error.message}`;
            knowledgeFeedback.style.color = '#dc3545';
        } finally {
            submitButton.disabled = false;
            submitButton.textContent = originalButtonText;
        }
    }

    webForm.addEventListener('submit', (e) => handleKnowledgeForm(e, 'web'));
    youtubeForm.addEventListener('submit', (e) => handleKnowledgeForm(e, 'youtube'));
    pdfForm.addEventListener('submit', (e) => handleKnowledgeForm(e, 'pdf'));
});