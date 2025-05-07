async function QCFetch(url, body, server_public_key) {
  const key = await generate_key();
  const encrypted_body = await assymetric_encrypt(
    server_public_key,
    JSON.stringify({ key: key, data: body })
  );

  TransparentCSS.log({}, `Encrypted body: ${encrypted_body}`);

  const response = await fetch(url, {
    body: encrypted_body,
    method: "POST",
    headers: {
      "Content-type": "application/json; charset=UTF-8",
    },
  });

  if (!response || !response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`);
  }

  const text = await response.text();
  const result = await decrypt(key, text);
  return result;
}
