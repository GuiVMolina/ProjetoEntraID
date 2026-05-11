function generateToken() {
  const name = document.getElementById("enc_name").value;
  const role = document.getElementById("enc_role").value;
  const key = document.getElementById("enc_key").value;

  const header = { alg: "HS256", typ: "JWT" };

  const payload = {
    iss: "https://sts.windows.net/senai-tenant/",
    name: name,
    roles: [role],
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
  };

  const sHeader = JSON.stringify(header);
  const sPayload = JSON.stringify(payload);

  const token = KJUR.jws.JWS.sign("HS256", sHeader, sPayload, { utf8: key });

  const parts = token.split(".");
  document.getElementById("generated_token").innerHTML = `
        <span style="color:#fb278d" title="Cabeçalho">${parts[0]}</span><span style="color:white">.</span><span style="color:#00ffff" title="Payload">${parts[1]}</span><span style="color:white">.</span><span style="color:#7ed321" title="Assinatura">${parts[2]}</span>
    `;

  document.getElementById("dec_input").value = token;
}

function verifyToken() {
  const token = document.getElementById("dec_input").value;
  const key = document.getElementById("enc_key").value;
  const statusBox = document.getElementById("status_box");
  const msg = document.getElementById("status_msg");
  const output = document.getElementById("dec_output");

  try {
    const isValid = KJUR.jws.JWS.verify(token, { utf8: key }, ["HS256"]);
    const decoded = KJUR.jws.JWS.parse(token);
    output.innerText = JSON.stringify(decoded.payloadObj, null, 4);

    statusBox.style.display = "block";

    if (isValid) {
      statusBox.style.background = "rgba(0, 255, 0, 0.2)";
      statusBox.style.border = "1px solid #00ff00";
      msg.innerText = "Assinatura ok: Identidade validada, acesso autorizado";
      document.getElementById("status_icon").innerText = "✅";
    } else {
      statusBox.style.background = "rgba(255, 0, 0, 0.2)";
      statusBox.style.border = "1px solid #ff0000";
      msg.innerText = "Erro de assinatura: Token corrompido ou chave incorreta";
      document.getElementById("status_icon").innerText = "❌";
    }
  } catch (error) {
    statusBox.style.display = "block";
    statusBox.style.background = "rgba(255, 0, 0, 0.2)";
    msg.innerText = "Erro crítico: Estrutura JWT inválida";
  }
}
