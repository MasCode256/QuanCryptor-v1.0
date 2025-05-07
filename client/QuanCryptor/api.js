async function isUserHasAccount() {
  const response = await pywebview.api.is_user_has_account();
  return response;
}

function printToConsole(...text) {
  try {
    /*text.forEach((str) => {
      pywebview.api.show_message(str);
    });*/

    pywebview.api.show_message(text.join(" "));
  } catch (error) {
    alert(`[printToConsole()] Critical JavaScript error: ${error}`);
  }
}

async function sha256(data) {
  try {
    const response = await pywebview.api.sha256(data);
    return response;
  } catch (error) {
    alert(`[sha256()] Critical JavaScript error: ${error}`);
  }
}

async function check_password(password, password_hash) {
  const response = await pywebview.api.check_password(password, password_hash);
  return response;
}

async function write_to_file(path, data) {
  const response = await pywebview.api.write_to_file(path, data);
  return response;
}
