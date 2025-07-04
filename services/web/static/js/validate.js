document.addEventListener("DOMContentLoaded", () => {
    const usernameInput = document.getElementById("username");
    const usernameCheck = document.getElementById("username-check");

    if (usernameInput) {
        usernameInput.addEventListener("input", () => {
            const username = usernameInput.value.trim();

            if (username.length > 0) {
                fetch(`/check_username?username=${encodeURIComponent(username)}`)
                    .then(res => res.json())
                    .then(data => {
                        if (data.exists) {
                            usernameCheck.textContent = "Логин уже занят";
                            usernameCheck.style.color = "red";
                        } else {
                            usernameCheck.textContent = "Логин доступен";
                            usernameCheck.style.color = "green";
                        }
                    });
            } else {
                usernameCheck.textContent = "";
            }
        });
    }
});
