document.addEventListener("DOMContentLoaded", () => {
  const connect_to_server_button = document.getElementById("connect-to-server");
  const server_address_input = document.getElementById("server-address");
  const internal_server_password_input = document.getElementById(
    "internal-server-password"
  );
  const server_handshake_result = document.getElementById("result-0");
  const password_input = document.getElementById("password");
  const nickname_input = document.getElementById("nickname");

  var server = {
    url: "",
    public_key: "",
    internal_password: "",
    external_password: "",
    protocol: "http",
  };

  connect_to_server_button.addEventListener("click", async () => {
    try {
      const server_data = parseSlashCode(
        SERVER_URL_ENCODING,
        server_address_input.value
      );

      printToConsole("Connecting to", JSON.stringify(server_data));
      await fetch("http://" + server_data["url"] + "/get_public_key")
        .then((data) => {
          return data.text();
        })
        .then(async (public_key) => {
          //printToConsole(`Public key: ${public_key}`);
          const public_key_hash = await sha256(public_key);
          //printToConsole(`Public key hash: ${public_key_hash}`);

          if (public_key_hash == server_data["public_key_hash"]) {
            TransparentCSS.log(
              { color: "var(--success)" },
              `Открытый ключ сервера успешно получен.`
            );

            await fetch(
              `http://${server_data["url"]}/get_internal_password_hash`
            )
              .then((response) => {
                return response.text();
              })
              .then(async (internal_password_hash) => {
                const password_check_result = await check_password(
                  internal_server_password_input.value,
                  internal_password_hash
                );

                if (password_check_result) {
                  TransparentCSS.log(
                    { color: "var(--success)" },
                    `Хэш внутреннего пароля успешно получен.`
                  );

                  server = {
                    url: server_data["url"],
                    public_key: public_key,
                    internal_password: internal_server_password_input.value,
                    external_password: "",
                    protocol: "http",
                  };

                  const response = await write_to_file(
                    `./data/servers/${server_data["url"].replace(
                      ":",
                      "."
                    )}.json`,
                    JSON.stringify(server)
                  );

                  if (response == true) {
                    TransparentCSS.log(
                      { color: "var(--success)" },
                      `Данные сервера сохранены.`
                    );

                    document.getElementById("lr").classList.remove("hided");
                  } else {
                    TransparentCSS.log(
                      { color: "var(--error)" },
                      `Неизвестная ошибка при сохранении данных сервера. (результат: ${response})`
                    );
                  }
                } else {
                  TransparentCSS.log(
                    { color: "var(--error)" },
                    `Неправильный внутренний пароль или ошибка при его проверке (результат проверки: ${password_check_result}).`
                  );
                }
              })
              .catch((error) => {
                alert(
                  `JavaScript error: error fetching password hash: ${error}`
                );
                TransparentCSS.log(
                  { color: "var(--error)" },
                  `Error fetching password hash: ${error}`
                );
              });
          } else {
            TransparentCSS.log(
              { color: "var(--error)" },
              `Открытый ключ сервера получен, но его хэш не совпадает с хэшем SlashCode. Ваши данные могут быть перехвачены. Попробуйте соединиться ещё раз.`
            );
          }
        })
        .catch((error) => {
          alert(`JavaScript error: error fetching server public key: ${error}`);
          printToConsole(`Error fetching server public key: ${error}`);
          TransparentCSS.log(
            { color: "var(--error)" },
            `Error fetching server public key: ${error}`
          );
        });
    } catch (error) {
      alert(`JavaScript error: error handshaking with server: ${error}`);
      TransparentCSS.log(
        { color: "var(--error)" },
        `JavaScript error: error handshaking with server: ${error}`
      );
    }
  });

  let timeout_0 = 0;
  nickname_input.addEventListener("input", () => {
    clearTimeout(timeout_0);
    timeout_0 = setTimeout(async () => {
      let url = `${server.protocol}://${server.url}/is_account_exists`;
      try {
        const responce = await QCFetch(
          url,
          { nickname: nickname_input.value },
          server.public_key
        );
        TransparentCSS.log({}, `Result: ${responce}`);
      } catch (error) {
        TransparentCSS.log(
          { color: "var(--error)" },
          `Ошибка при проверке существования аккаунта: ${error}`
        );
      }
    }, 1500);
  });
});
