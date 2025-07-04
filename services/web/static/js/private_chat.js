const chatBox = document.getElementById("chat-box");
const messageInput = document.getElementById("message-input");
const sendBtn = document.getElementById("send-btn");
const charCount = document.getElementById("char-count");

const chatId = "{{ chat_id }}";

messageInput.addEventListener("input", () => {
    charCount.textContent = `${messageInput.value.length}/500`;
});

sendBtn.addEventListener("click", sendMessage);

messageInput.addEventListener("keypress", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
    }
});

function sendMessage() {
    const message = messageInput.value.trim();
    if (message.length === 0 || message.length > 500) return;

    socket.emit("send_private_message", {
        message,
        chat_id: window.currentChatId
    });

    messageInput.value = "";
    charCount.textContent = "0/500";
}

socket.on("receive_private_message", (data) => {
    const msg = document.createElement("div");
    msg.textContent = `@${data.username} [${data.timestamp}]: ${data.message}`;
    chatBox.appendChild(msg);
    chatBox.scrollTop = chatBox.scrollHeight;
});

socket.emit("join_private_chat", {
    chat_id: window.currentChatId
});

socket.on("chat_deleted", (data) => {
    if (data.chat_id === window.currentChatId) {
        alert("Чат был удалён!");
        window.location.href = "/connect_private_chat";
    }
});