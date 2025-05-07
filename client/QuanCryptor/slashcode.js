function parseSlashCode(encoding_str = "", link = "", delimiter = "/") {
  const encoding = encoding_str.split(delimiter);
  const data = link.split(delimiter);

  let ret = {};

  if (encoding.length != data.length) {
    throw new Error(
      "Decoding SlashCode: the data is not compatible with the encoding."
    );
  }

  data.forEach((element, index) => {
    ret[encoding[index]] = element;
  });

  return ret;
}

const SERVER_URL_ENCODING = `url/public_key_hash`;
