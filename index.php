<?php
$pkeyFile = __DIR__ . "/pkeyconfig.xrm-ms";

if (!file_exists($pkeyFile)) {
    die("No se encontró el archivo pkeyconfig.xrm-ms.");
}

$xmlContent = file_get_contents($pkeyFile);
$xml = simplexml_load_string($xmlContent);
$pkeyNode = $xml->xpath('./*[local-name()="license"]/*[local-name()="otherInfo"]/*[local-name()="infoTables"]/*[local-name()="infoList"]/*[local-name()="infoBin"][@name="pkeyConfigData"]');
$pkeyDataXml = base64_decode((string)$pkeyNode[0]);
$pkeyData = simplexml_load_string($pkeyDataXml);

$configs = $pkeyData->xpath('./*[local-name()="Configurations"]/*[local-name()="Configuration"]');
$ranges  = $pkeyData->xpath('./*[local-name()="KeyRanges"]/*[local-name()="KeyRange"]');
$pubkeys = $pkeyData->xpath('./*[local-name()="PublicKeys"]/*[local-name()="PublicKey"]');

// Filtrar configuraciones válidas
$validConfigs = [];
foreach ($configs as $c) {
    $configId = (string)$c->ActConfigId;
    $groupId  = (string)$c->RefGroupId;

    if ($groupId === "999999") continue;

    $pubkey = null;
    foreach ($pubkeys as $p) {
        if ((string)$p->GroupId === $groupId) {
            $pubkey = $p;
            break;
        }
    }
    if (!$pubkey || (string)$pubkey->AlgorithmId !== "msft:rm/algorithm/pkey/2009") continue;

    $hasValidRange = false;
    foreach ($ranges as $r) {
        if ((string)$r->RefActConfigId === $configId && strtolower((string)$r->IsValid) === "true") {
            $hasValidRange = true;
            break;
        }
    }

    if ($hasValidRange) {
        $validConfigs[$groupId] = (string)$c->ProductDescription;
    }
}
?>
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <title>Generador de claves de Windows</title>
  <style>
    body {
      font-family: "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: #f4f6f9;
      margin: 0;
      padding: 0;
      color: #333;
    }
    .container {
      max-width: 600px;
      margin: 4rem auto;
      background: #fff;
      padding: 2rem 3rem;
      border-radius: 8px;
      box-shadow: 0 6px 20px rgba(0,0,0,0.1);
    }
    h1 {
      font-size: 1.8rem;
      margin-bottom: 1.5rem;
      color: #2c3e50;
      text-align: center;
    }
    label {
      font-weight: 600;
      margin-top: 1rem;
      display: block;
    }
    select, input, textarea {
      width: 100%;
      padding: .7rem;
      margin-top: .5rem;
      border: 1px solid #ccc;
      border-radius: 6px;
      font-size: 1rem;
      transition: border-color .3s;
    }
    select:focus, input:focus, textarea:focus {
      border-color: #0078d7;
      outline: none;
    }
    button {
      margin-top: 2rem;
      width: 100%;
      padding: .9rem;
      font-size: 1.1rem;
      font-weight: bold;
      color: #fff;
      background: linear-gradient(135deg, #0078d7, #005a9e);
      border: none;
      border-radius: 6px;
      cursor: pointer;
      transition: background .3s;
    }
    button:hover {
      background: linear-gradient(135deg, #005a9e, #004578);
    }
    .note {
      font-size: .9rem;
      color: #666;
      margin-top: 1rem;
      text-align: center;
    }
    textarea {
      margin-top: 1.5rem;
      height: 200px;
      resize: vertical;
      font-family: ui-monospace, monospace;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>Generador de claves de Windows</h1>
    <form id="keyForm">
      <label for="sku">Selecciona edición (SKU):</label>
      <select name="sku" id="sku" required>
        <?php foreach ($validConfigs as $groupId => $description): ?>
          <option value="<?= htmlspecialchars($groupId) ?>">
            <?= htmlspecialchars($description) ?>
          </option>
        <?php endforeach; ?>
      </select>

      <label for="count">Número de claves a generar:</label>
      <input type="number" name="count" id="count" min="1" max="100" value="10" required>

      <button type="submit">Generar claves</button>
    </form>

    <textarea id="result" placeholder="Aquí aparecerán las claves generadas..." readonly></textarea>
    <p class="note">Elige la edición y la cantidad de claves que deseas generar.</p>
  </div>

  <script>
    document.getElementById('keyForm').addEventListener('submit', function(e) {
      e.preventDefault();
      const formData = new FormData(this);

      fetch('generate.php', {
        method: 'POST',
        body: formData
      })
      .then(res => res.text())
      .then(data => {
        document.getElementById('result').value = data.trim();
      })
      .catch(err => {
        document.getElementById('result').value = "Error al generar claves: " + err;
      });
    });
  </script>
</body>
</html>
